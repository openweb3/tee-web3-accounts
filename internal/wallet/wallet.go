// Package wallet 用配置在 TEE 里的助记词实时派生 Web3 账户私钥。
//
// 设计要点：**私钥从不落盘、从不加密存储**。任意索引对应的私钥都由助记词现场
// 派生，进程退出即消失；TEE 内持久化的只有「索引 -> 密码验证子」的映射。
package wallet

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// DefaultAccountRootPath 是以太坊标准的 BIP-44 账户根路径。
// 第 i 个账户的完整路径是它后面再接一个非硬化索引，即 m/44'/60'/0'/0/i。
const DefaultAccountRootPath = "m/44'/60'/0'/0"

// ErrHashSize 表示待签名的哈希长度不是 32 字节。
var ErrHashSize = errors.New("wallet: 待签名哈希必须是 32 字节")

// ErrSignatureSize 表示签名长度不是 65 字节。
var ErrSignatureSize = errors.New("wallet: 签名必须是 65 字节")

// Config 是构造钱包所需的全部参数。
type Config struct {
	// Mnemonic 是 TEE 启动时配置的 BIP-39 英文助记词，是所有私钥的唯一来源。
	Mnemonic string
	// Passphrase 是 BIP-39 可选的额外口令，通常留空。
	Passphrase string
	// AccountRootPath 是账户根路径，留空则使用 DefaultAccountRootPath。
	AccountRootPath string
}

// Wallet 是常驻内存的 HD 钱包，只保存账户根节点，不保存任何账户的私钥。
type Wallet struct {
	root     *bip32Node
	rootPath string
}

// Open 校验助记词并生成钱包。助记词非法时直接报错，不做任何降级。
func Open(cfg Config) (*Wallet, error) {
	if err := ValidateMnemonic(cfg.Mnemonic); err != nil {
		return nil, err
	}

	rootPath := cfg.AccountRootPath
	if rootPath == "" {
		rootPath = DefaultAccountRootPath
	}

	seed, err := mnemonicToSeed(cfg.Mnemonic, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("wallet: 派生种子失败: %w", err)
	}
	defer zero(seed)

	master, err := newMasterNode(seed)
	if err != nil {
		return nil, err
	}
	root, err := master.derivePath(rootPath)
	if err != nil {
		master.key.Zero()
		return nil, err
	}
	// 账户根节点是独立派生出来的，主私钥用完立刻抹掉。
	if root != master {
		master.key.Zero()
	}

	return &Wallet{root: root, rootPath: rootPath}, nil
}

// AccountRootPath 返回钱包使用的账户根路径。
func (w *Wallet) AccountRootPath() string { return w.rootPath }

// AccountPath 返回指定索引的完整派生路径。
func (w *Wallet) AccountPath(index uint32) string {
	return fmt.Sprintf("%s/%d", w.rootPath, index)
}

// Account 实时派生指定索引的账户。
//
// 返回的 Account 持有私钥，调用方用完必须立刻 Destroy，且不要把 Account 缓存起来。
func (w *Wallet) Account(index uint32) (*Account, error) {
	node, err := w.root.child(index)
	if err != nil {
		return nil, fmt.Errorf("wallet: 派生账户 %d 失败: %w", index, err)
	}
	return &Account{
		Index:   index,
		Path:    w.AccountPath(index),
		Address: addressFromPubKey(node.key.PubKey()),
		priv:    node.key,
	}, nil
}

// Address 只返回指定索引的地址，供查询接口使用。
func (w *Wallet) Address(index uint32) (string, error) {
	account, err := w.Account(index)
	if err != nil {
		return "", err
	}
	defer account.Destroy()
	return account.Address, nil
}

// Account 是一个实时派生出来的账户。
type Account struct {
	Index   uint32
	Path    string
	Address string

	priv *secp256k1.PrivateKey
}

// Sign 用账户私钥对 32 字节哈希做 secp256k1 可恢复签名，
// 输出以太坊约定的 65 字节 r || s || v（v = 27 + recovery id）。
func (a *Account) Sign(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("%w（实际 %d 字节）", ErrHashSize, len(hash))
	}

	// 紧凑签名格式为 [27 + recovery id][r][s]，恰好与以太坊的 v 约定一致，
	// 只需把首字节挪到末尾。
	compact := ecdsa.SignCompact(a.priv, hash, false)
	signature := make([]byte, 65)
	copy(signature[:64], compact[1:])
	signature[64] = compact[0]
	return signature, nil
}

// Destroy 抹掉账户私钥在内存中的副本。
func (a *Account) Destroy() {
	if a.priv != nil {
		a.priv.Zero()
		a.priv = nil
	}
}

// RecoverAddress 从签名（65 字节 r || s || v）与哈希里恢复出签名者地址。
//
// 与 Sign 完全对称，放在这里是为了让服务端自检和调用方验签都不需要依赖内部实现。
func RecoverAddress(hash, signature []byte) (string, error) {
	if len(hash) != 32 {
		return "", fmt.Errorf("%w（实际 %d 字节）", ErrHashSize, len(hash))
	}
	if len(signature) != 65 {
		return "", fmt.Errorf("%w（实际 %d 字节）", ErrSignatureSize, len(signature))
	}

	// 还原成 lib 认的紧凑格式 [27 + recovery id][r][s]。
	compact := make([]byte, 65)
	compact[0] = signature[64]
	copy(compact[1:], signature[:64])

	pub, _, err := ecdsa.RecoverCompact(compact, hash)
	if err != nil {
		return "", fmt.Errorf("wallet: 恢复公钥失败: %w", err)
	}
	return addressFromPubKey(pub), nil
}

// zero 覆写字节切片。
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
