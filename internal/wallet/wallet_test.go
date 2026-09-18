package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// hardhatMnemonic 是 Hardhat / Anvil 默认的测试助记词，它的派生地址是公开已知的，
// 适合做端到端对码验证。
const hardhatMnemonic = "test test test test test test test test test test test junk"

// hardhatAddresses 是上述助记词在 m/44'/60'/0'/0/{i} 路径下的地址（EIP-55 形式）。
var hardhatAddresses = []string{
	"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
	"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
	"0x90F79bf6EB2c4f870365E785982E1f101E93b906",
	"0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
}

func TestMnemonicToSeed(t *testing.T) {
	t.Parallel()

	// BIP-39 官方测试向量（Trezor vectors.json，passphrase 为空）。
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const want = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
		"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

	seed, err := mnemonicToSeed(mnemonic, "")
	if err != nil {
		t.Fatalf("mnemonicToSeed: %v", err)
	}
	if got := hex.EncodeToString(seed); got != want {
		t.Fatalf("种子不匹配\n got %s\nwant %s", got, want)
	}
}

func TestValidateMnemonic(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mnemonic string
		wantErr  bool
	}{
		{"Hardhat 助记词", hardhatMnemonic, false},
		{"官方向量", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", false},
		{"24 词", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", false},
		{"多余空白", "  " + hardhatMnemonic + "  ", false},
		{"词数不对", "test test test", true},
		{"空", "", true},
		{"词表外的词", strings.Replace(hardhatMnemonic, "junk", "notaword", 1), true},
		{"校验和不匹配", strings.Replace(hardhatMnemonic, "junk", "zoo", 1), true},
		{"中文字符", "测试 测试 测试 测试 测试 测试 测试 测试 测试 测试 测试 测试", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateMnemonic(tt.mnemonic)
			if tt.wantErr && err == nil {
				t.Fatal("期望报错，实际通过")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("期望通过，实际报错: %v", err)
			}
		})
	}
}

func TestOpenRejectsInvalidConfigPath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"44/60", "m/44'/abc", "m/44'/2147483648", ""} {
		cfg := Config{Mnemonic: hardhatMnemonic}
		if path == "" {
			// 空路径表示使用默认值，不该报错。
			if _, err := Open(cfg); err != nil {
				t.Fatalf("空路径应当使用默认值，却报错: %v", err)
			}
			continue
		}
		cfg.AccountRootPath = path
		if _, err := Open(cfg); err == nil {
			t.Fatalf("路径 %q 期望报错，实际通过", path)
		}
	}
}

func TestDeriveHardhatAddresses(t *testing.T) {
	t.Parallel()

	w, err := Open(Config{Mnemonic: hardhatMnemonic})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if w.AccountRootPath() != DefaultAccountRootPath {
		t.Fatalf("默认账户根路径 = %q", w.AccountRootPath())
	}

	for index, want := range hardhatAddresses {
		account, err := w.Account(uint32(index))
		if err != nil {
			t.Fatalf("Account(%d): %v", index, err)
		}

		if account.Address != want {
			t.Errorf("index %d 地址不匹配\n got %s\nwant %s", index, account.Address, want)
		}
		wantPath := fmt.Sprintf("%s/%d", DefaultAccountRootPath, index)
		if account.Path != wantPath {
			t.Errorf("index %d 路径 = %q, want %q", index, account.Path, wantPath)
		}

		// 查询接口走的是完全独立的代码路径，必须得到同一个地址。
		address, err := w.Address(uint32(index))
		if err != nil {
			t.Fatalf("Address(%d): %v", index, err)
		}
		if address != want {
			t.Errorf("Address(%d) = %s, want %s", index, address, want)
		}

		account.Destroy()
	}
}

// TestDeriveOfficialVectorAddresses 用 BIP-39 官方向量助记词再验一遍，
// 与 Hardhat 向量互补：两者来自不同的公开来源。
func TestDeriveOfficialVectorAddresses(t *testing.T) {
	t.Parallel()

	w, err := Open(Config{Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := []string{
		"0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
		"0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
		"0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
		"0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E",
	}
	for index, expected := range want {
		address, err := w.Address(uint32(index))
		if err != nil {
			t.Fatalf("Address(%d): %v", index, err)
		}
		if address != expected {
			t.Errorf("index %d 地址不匹配\n got %s\nwant %s", index, address, expected)
		}
	}
}

func TestEIP55Checksum(t *testing.T) {
	t.Parallel()

	// EIP-55 规范里给出的测试向量。
	vectors := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, want := range vectors {
		raw, err := hex.DecodeString(strings.TrimPrefix(want, "0x"))
		if err != nil {
			t.Fatalf("解码 %s: %v", want, err)
		}
		if got := eip55(raw); got != want {
			t.Errorf("eip55 不匹配\n got %s\nwant %s", got, want)
		}
	}
}

func TestSignAndRecover(t *testing.T) {
	t.Parallel()

	w, err := Open(Config{Mnemonic: hardhatMnemonic})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	account, err := w.Account(1)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	defer account.Destroy()

	hash := keccak256([]byte("hello tee"))
	signature, err := account.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signature) != 65 {
		t.Fatalf("签名长度 = %d, want 65", len(signature))
	}
	if v := signature[64]; v != 27 && v != 28 {
		t.Fatalf("v = %d, 期望 27 或 28", v)
	}

	// 用签名和哈希反推公钥，再算地址 —— 这同时验证了签名本身和地址派生。
	compact := make([]byte, 65)
	compact[0] = signature[64]
	copy(compact[1:], signature[:64])
	pub, _, err := ecdsa.RecoverCompact(compact, hash)
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if got := addressFromPubKey(pub); got != hardhatAddresses[1] {
		t.Errorf("恢复出的地址 = %s, want %s", got, hardhatAddresses[1])
	}

	// RFC6979 确定性签名：同样的输入必须得到同样的签名。
	again, err := account.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if hex.EncodeToString(again) != hex.EncodeToString(signature) {
		t.Error("签名不是确定性的")
	}
}

func TestRecoverAddress(t *testing.T) {
	t.Parallel()

	w, err := Open(Config{Mnemonic: hardhatMnemonic})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	account, err := w.Account(2)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	defer account.Destroy()

	hash := keccak256([]byte("recover me"))
	signature, err := account.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	recovered, err := RecoverAddress(hash, signature)
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	if recovered != hardhatAddresses[2] {
		t.Errorf("恢复出的地址 = %s, want %s", recovered, hardhatAddresses[2])
	}

	// 换个哈希就恢复不出原地址，说明恢复过程真的在用哈希。
	other, err := RecoverAddress(keccak256([]byte("something else")), signature)
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	if other == hardhatAddresses[2] {
		t.Error("换哈希后仍恢复出原地址，恢复逻辑有问题")
	}

	if _, err := RecoverAddress(hash[:31], signature); !errors.Is(err, ErrHashSize) {
		t.Errorf("短哈希: %v", err)
	}
	if _, err := RecoverAddress(hash, signature[:64]); !errors.Is(err, ErrSignatureSize) {
		t.Errorf("短签名: %v", err)
	}
}

func TestSignRejectsBadHashSize(t *testing.T) {
	t.Parallel()

	w, err := Open(Config{Mnemonic: hardhatMnemonic})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	account, err := w.Account(0)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	defer account.Destroy()

	for _, size := range []int{0, 31, 33, 64} {
		if _, err := account.Sign(make([]byte, size)); err == nil {
			t.Errorf("%d 字节的哈希期望报错", size)
		}
	}
}

func TestDestroyClearsKey(t *testing.T) {
	t.Parallel()

	w, err := Open(Config{Mnemonic: hardhatMnemonic})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	account, err := w.Account(0)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	account.Destroy()
	if account.priv != nil {
		t.Error("Destroy 之后私钥引用未被清空")
	}
	account.Destroy() // 重复调用必须安全
}

func TestParsePath(t *testing.T) {
	t.Parallel()

	got, err := parsePath("m/44'/60'/0'/0/7")
	if err != nil {
		t.Fatalf("parsePath: %v", err)
	}
	want := []uint32{44 + hardenedOffset, 60 + hardenedOffset, hardenedOffset, 0, 7}
	if len(got) != len(want) {
		t.Fatalf("长度 = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 段 = %d, want %d", i, got[i], want[i])
		}
	}

	if indices, err := parsePath("m"); err != nil || len(indices) != 0 {
		t.Errorf(`parsePath("m") = %v, %v`, indices, err)
	}
}
