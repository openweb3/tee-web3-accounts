package wallet

import (
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// addressFromPubKey 按以太坊规则由公钥算出地址：取未压缩公钥去掉 0x04 前缀后的
// Keccak-256 哈希的最后 20 字节，并加 EIP-55 校验和。
func addressFromPubKey(pub *secp256k1.PublicKey) string {
	uncompressed := pub.SerializeUncompressed() // 65 字节，首字节 0x04
	digest := keccak256(uncompressed[1:])
	return eip55(digest[12:])
}

// eip55 把 20 字节地址编码成 EIP-55 混合大小写形式。
func eip55(addr []byte) string {
	lower := hex.EncodeToString(addr)
	digest := keccak256([]byte(lower))

	out := make([]byte, 0, 2+len(lower))
	out = append(out, '0', 'x')
	for i := range len(lower) {
		c := lower[i]
		if c >= 'a' && c <= 'f' {
			// 用哈希里对应的 nibble 决定这个字母是否大写。
			nibble := digest[i/2]
			if i%2 == 0 {
				nibble >>= 4
			} else {
				nibble &= 0x0f
			}
			if nibble >= 8 {
				c -= 'a' - 'A'
			}
		}
		out = append(out, c)
	}
	return string(out)
}

// keccak256 是 Keccak-256（原始 Keccak 填充，非 NIST SHA3-256），以太坊用它。
func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}
