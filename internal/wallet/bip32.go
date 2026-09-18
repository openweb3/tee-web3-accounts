package wallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// hardenedOffset 是 BIP-32 中硬化索引的起点（2^31）。
const hardenedOffset = 0x80000000

// ErrDerive 表示 BIP-32 派生失败。按规范这两个分支都应当换下一个索引重试，
// 但概率约为 2^-127，因此这里只作为不可达的防御分支返回错误。
var ErrDerive = errors.New("wallet: HD 派生失败")

// bip32Node 是 BIP-32 的一个扩展私钥节点。
type bip32Node struct {
	key  *secp256k1.PrivateKey
	code [32]byte // 链码 chain code
}

// newMasterNode 由种子生成 BIP-32 主节点：I = HMAC-SHA512("Bitcoin seed", seed)。
func newMasterNode(seed []byte) (*bip32Node, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	sum := mac.Sum(nil)
	defer zero(sum)

	var left, code [32]byte
	copy(left[:], sum[:32])
	copy(code[:], sum[32:])

	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetBytes(&left); overflow != 0 || scalar.IsZero() {
		zero(left[:])
		return nil, fmt.Errorf("%w: 种子不产生合法的主私钥", ErrDerive)
	}
	zero(left[:])
	key := scalarToKey(&scalar)
	scalar.Zero()
	return &bip32Node{key: key, code: code}, nil
}

// child 执行 BIP-32 的 CKDpriv：父扩展私钥 -> 子扩展私钥。
func (n *bip32Node) child(index uint32) (*bip32Node, error) {
	// data = 0x00 || ser256(k_par) || ser32(i)   硬化
	//      = serP(point(k_par)) || ser32(i)      非硬化
	var data [37]byte
	defer zero(data[:])

	if index >= hardenedOffset {
		var parentKey [32]byte
		n.key.Key.PutBytes(&parentKey)
		copy(data[1:33], parentKey[:])
		zero(parentKey[:])
	} else {
		copy(data[:33], n.key.PubKey().SerializeCompressed())
	}
	binary.BigEndian.PutUint32(data[33:], index)

	mac := hmac.New(sha512.New, n.code[:])
	mac.Write(data[:])
	sum := mac.Sum(nil)
	defer zero(sum)

	var left [32]byte
	copy(left[:], sum[:32])
	defer zero(left[:])
	var code [32]byte
	copy(code[:], sum[32:])

	var tweak secp256k1.ModNScalar
	if overflow := tweak.SetBytes(&left); overflow != 0 {
		return nil, fmt.Errorf("%w: 索引 %d 的左半部分超出曲线阶", ErrDerive, index)
	}

	// k_i = (parse256(I_L) + k_par) mod n
	var child secp256k1.ModNScalar
	child.Set(&n.key.Key)
	child.Add(&tweak)
	tweak.Zero()
	if child.IsZero() {
		return nil, fmt.Errorf("%w: 索引 %d 派生出零私钥", ErrDerive, index)
	}
	key := scalarToKey(&child)
	child.Zero()
	return &bip32Node{key: key, code: code}, nil
}

// derivePath 从当前节点出发，按 BIP-32 路径逐级派生出子节点。
// 路径为 "m" 时返回节点自身。中间节点用完即抹掉：Go 的 GC 不会清零释放的内存，
// 不主动归零的话，硬化派生出的各级父私钥会一直留在堆里。
func (n *bip32Node) derivePath(path string) (*bip32Node, error) {
	indices, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	node := n
	for _, index := range indices {
		next, err := node.child(index)
		if err != nil {
			return nil, err
		}
		if node != n { // 入口节点归调用方所有，不在这里清理
			node.key.Zero()
			zero(node.code[:])
		}
		node = next
	}
	return node, nil
}

// parsePath 解析 "m/44'/60'/0'/0/0" 形式的派生路径。
// 硬化标记接受 '、h、H 三种写法。
func parsePath(path string) ([]uint32, error) {
	parts := strings.Split(path, "/")
	if len(parts) == 0 || (parts[0] != "m" && parts[0] != "M") {
		return nil, fmt.Errorf("wallet: 派生路径 %q 必须以 m 开头", path)
	}

	indices := make([]uint32, 0, len(parts)-1)
	for _, part := range parts[1:] {
		hardened := false
		if part != "" {
			switch part[len(part)-1] {
			case '\'', 'h', 'H':
				hardened = true
				part = part[:len(part)-1]
			}
		}
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil || value >= hardenedOffset {
			return nil, fmt.Errorf("wallet: 派生路径 %q 中的 %q 不是合法索引", path, part)
		}
		if hardened {
			value += hardenedOffset
		}
		indices = append(indices, uint32(value))
	}
	return indices, nil
}

// scalarToKey 把模标量转成 secp256k1 私钥，并抹掉中间的字节副本。
func scalarToKey(scalar *secp256k1.ModNScalar) *secp256k1.PrivateKey {
	var raw [32]byte
	scalar.PutBytes(&raw)
	defer zero(raw[:])
	return secp256k1.PrivKeyFromBytes(raw[:])
}
