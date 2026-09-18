package store

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// algorithmArgon2id 是目前唯一支持的密码验证算法。
const algorithmArgon2id = "argon2id"

// SaltLength 是随机盐的长度（字节）。
const SaltLength = 16

// ErrUnauthorized 表示索引不存在或密码不正确。两种情况共用同一个错误，
// 不向调用方区分，避免把「某索引是否存在」变成探测信号。
var ErrUnauthorized = errors.New("store: 索引或密码不正确")

// Argon2Params 是密码验证子的代价参数。
//
// 密码是这套托管服务上唯一的身份凭据，所以用内存硬的 Argon2id，单次约 64 MiB、
// 百毫秒量级，让离线爆破变得昂贵。
type Argon2Params struct {
	Time      uint32 // 迭代轮数
	MemoryKiB uint32 // 内存用量
	Threads   uint8  // 并行度
	KeyLength uint32 // 派生密钥长度
}

// DefaultArgon2Params 是推荐的默认代价参数，与 OWASP 对 Argon2id 的建议一致。
var DefaultArgon2Params = Argon2Params{
	Time:      3,
	MemoryKiB: 64 * 1024,
	Threads:   4,
	KeyLength: 32,
}

// validate 兜住明显不合理的参数，避免被篡改的记录导致巨量内存分配。
func (p Argon2Params) validate() error {
	switch {
	case p.Time == 0 || p.Time > 32:
		return fmt.Errorf("store: argon2 迭代轮数 %d 超出 [1,32]", p.Time)
	case p.MemoryKiB < 8 || p.MemoryKiB > 1<<20:
		return fmt.Errorf("store: argon2 内存用量 %d KiB 超出 [8,1048576]", p.MemoryKiB)
	case p.Threads == 0 || p.Threads > 64:
		return fmt.Errorf("store: argon2 并行度 %d 超出 [1,64]", p.Threads)
	case p.KeyLength != 32:
		return fmt.Errorf("store: argon2 密钥长度必须是 32，实际 %d", p.KeyLength)
	}
	return nil
}

// PasswordHash 记录了一次 Argon2id 派生的全部输入与输出参数，因此日后调整代价
// 参数或迁移算法时，老记录仍然能校验。
type PasswordHash struct {
	Algorithm string `json:"algorithm"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
	Key       []byte `json:"key"`
}

// hashPassword 用随机盐派生密码验证子。
func hashPassword(password string, params Argon2Params) (PasswordHash, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return PasswordHash{}, fmt.Errorf("store: 生成盐失败: %w", err)
	}

	passwordBytes := []byte(password)
	defer zero(passwordBytes)
	key := argon2.IDKey(passwordBytes, salt, params.Time, params.MemoryKiB, params.Threads, params.KeyLength)

	return PasswordHash{
		Algorithm: algorithmArgon2id,
		Time:      params.Time,
		MemoryKiB: params.MemoryKiB,
		Threads:   params.Threads,
		Salt:      salt,
		Key:       key,
	}, nil
}

// matches 用记录里自带的参数重新派生并做常数时间比较。
func (h PasswordHash) matches(password string) bool {
	if h.Algorithm != algorithmArgon2id || h.validate() != nil {
		return false
	}

	passwordBytes := []byte(password)
	defer zero(passwordBytes)
	key := argon2.IDKey(passwordBytes, h.Salt, h.Time, h.MemoryKiB, h.Threads, uint32(len(h.Key)))
	defer zero(key)
	return subtle.ConstantTimeCompare(key, h.Key) == 1
}

func (h PasswordHash) validate() error {
	if h.Algorithm != algorithmArgon2id {
		return fmt.Errorf("store: 不支持的密码算法 %q", h.Algorithm)
	}
	if len(h.Salt) < SaltLength {
		return fmt.Errorf("store: 盐长度 %d 太短", len(h.Salt))
	}
	if len(h.Key) == 0 {
		return errors.New("store: 密码验证子为空")
	}
	return Argon2Params{
		Time:      h.Time,
		MemoryKiB: h.MemoryKiB,
		Threads:   h.Threads,
		KeyLength: uint32(len(h.Key)),
	}.validate()
}

// zero 覆写字节切片。
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
