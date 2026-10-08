package store

import (
	"crypto/rand"
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

// argon2Ceiling 是单次派生允许的绝对上限，配置与存量记录共用同一个上界（见
// Argon2Params.Validate）。收敛成一套是为了根除「两套上限打架」：以前配置能
// 顶到 1 GiB，而校验只认 256 MiB，运维把参数配高后新建的账户会在每次校验时被
// ceiling 判为「密码错误」，正确密码永远 401 且无任何日志指向真因，账户静默
// 永久不可用。现在创建用的参数天然 ≤ 校验允许的上限，不可能造出校验不了的记录。
//
// 上限同时是资源护栏：即使完整性密钥泄露、文件被伪造，一条记录也无法把单次
// 校验的内存顶到 1 GiB。
var argon2Ceiling = Argon2Params{
	Time:      16,
	MemoryKiB: 256 * 1024,
	Threads:   8,
	KeyLength: 32,
}

// Validate 校验代价参数是否落在 [下界, argon2Ceiling] 之内。配置（Open 时）与
// 存量记录（h.validate()）都走这一个入口，因此不存在「创建合法但校验必拒」的
// 参数区间，也不可能被一条记录顶出巨量内存分配。
func (p Argon2Params) Validate() error {
	switch {
	case p.Time == 0 || p.Time > argon2Ceiling.Time:
		return fmt.Errorf("store: argon2 迭代轮数 %d 超出 [1,%d]", p.Time, argon2Ceiling.Time)
	case p.MemoryKiB < 8 || p.MemoryKiB > argon2Ceiling.MemoryKiB:
		return fmt.Errorf("store: argon2 内存用量 %d KiB 超出 [8,%d]", p.MemoryKiB, argon2Ceiling.MemoryKiB)
	case p.Threads == 0 || p.Threads > argon2Ceiling.Threads:
		return fmt.Errorf("store: argon2 并行度 %d 超出 [1,%d]", p.Threads, argon2Ceiling.Threads)
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
	defer clear(passwordBytes)
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

// dummySalt 是「索引不存在」时跑等价 Argon2 用的固定盐。校验结果无人使用，
// 只为了把耗时拉到与真实校验同一个量级，抹平「索引不存在」与「密码错误」的时序差。
var dummySalt = []byte("tee-dummy-salt-0")

// dummyVerify 在索引不存在时跑一次等价的 Argon2。
func dummyVerify(password string, params Argon2Params) {
	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	key := argon2.IDKey(passwordBytes, dummySalt, params.Time, params.MemoryKiB, params.Threads, params.KeyLength)
	defer clear(key)
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
	}.Validate()
}
