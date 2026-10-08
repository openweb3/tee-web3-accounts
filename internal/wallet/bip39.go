package wallet

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"
)

// pbkdf2Rounds 和 seedLength 由 BIP-39 规定，不可改。
const (
	pbkdf2Rounds = 2048
	seedLength   = 64
)

// mnemonicWordCounts 是 BIP-39 定义的合法助记词词数。
var mnemonicWordCounts = map[int]struct{}{12: {}, 15: {}, 18: {}, 21: {}, 24: {}}

// englishWordIndex 把词表里的单词映射到它的 11 bit 下标（0..2047）。
var englishWordIndex = func() map[string]int {
	words := strings.Fields(bip39English)
	m := make(map[string]int, len(words))
	for i, w := range words {
		m[w] = i
	}
	return m
}()

// ErrMnemonic 表示配置的助记词不是合法的 BIP-39 英文助记词。
var ErrMnemonic = errors.New("wallet: 助记词不合法")

// ValidateMnemonic 校验助记词是否为合法的 BIP-39 英文助记词：词数、词表、校验和。
//
// 这个校验只在启动时做一次，目的是拦住「配错助记词」这类静默故障 —— 一旦助记词
// 与实际使用的不同，派生出的地址会整体改变且不做任何报错，用户资产将不可达。
//
// 只支持英文词表。BIP-39 要求先做 NFKD 归一化，英文词表全是 ASCII，归一化是恒等
// 变换，因此这里不需要引入 unicode 归一化依赖。
func ValidateMnemonic(mnemonic string) error {
	words := strings.Fields(mnemonic)
	if _, ok := mnemonicWordCounts[len(words)]; !ok {
		return fmt.Errorf("%w: 词数 %d 不在 12/15/18/21/24 之内", ErrMnemonic, len(words))
	}

	// 把每个单词还原成 11 bit，拼成整条比特串。
	bits := make([]bool, 0, len(words)*11)
	for _, w := range words {
		idx, ok := englishWordIndex[w]
		if !ok {
			return fmt.Errorf("%w: %q 不在 BIP-39 英文词表中", ErrMnemonic, w)
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, (idx>>uint(b))&1 == 1)
		}
	}

	// 比特串尾部是熵的 SHA-256 校验和，长度 = 熵长度 / 32。
	entropyBits := len(bits) * 32 / 33
	checksumBits := len(bits) - entropyBits
	entropy := make([]byte, entropyBits/8)
	for i := range entropyBits {
		if bits[i] {
			entropy[i/8] |= 1 << (7 - uint(i%8))
		}
	}

	sum := sha256.Sum256(entropy)
	for i := range checksumBits {
		want := (sum[i/8]>>(7-uint(i%8)))&1 == 1
		if bits[entropyBits+i] != want {
			return fmt.Errorf("%w: 校验和不匹配（很可能输错了某个单词）", ErrMnemonic)
		}
	}
	return nil
}

// mnemonicToSeed 按 BIP-39 用 PBKDF2-HMAC-SHA512 把助记词拉成 64 字节种子。
//
// passphrase 是 BIP-39 的可选额外口令（与用户密码无关，用户密码只用于身份校验）。
func mnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	// BIP-39 要求归一化空白后按单空格拼接；strings.Fields 顺带完成了 NFKD 中
	// 空白字符的等价处理。
	normalized := strings.Join(strings.Fields(mnemonic), " ")
	return pbkdf2.Key(sha512.New, normalized, []byte("mnemonic"+passphrase), pbkdf2Rounds, seedLength)
}
