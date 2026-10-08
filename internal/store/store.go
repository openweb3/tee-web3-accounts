// Package store 持久化「账户索引 -> 密码验证子」的映射。
//
// 这里刻意只存密码验证子，不存密码、也不存任何私钥：私钥由 TEE 里的助记词在现场
// 派生，进程退出即消失。记录里额外保留一份地址，作用是给助记词做一致性护栏 ——
// 如果 TEE 启动时换了一个助记词，派生出的地址会整体改变，凭这份地址就能立刻发现。
package store

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
)

// fileVersion 是账户库文件的格式版本。
const fileVersion = 1

// Deriver 由调用方注入：给定索引返回该账户的地址。这样 store 完全不需要知道任何
// 钱包或曲线细节，索引分配与派生结果能在一个锁内原子完成。
type Deriver func(index uint32) (address string, err error)

// Account 是一条持久化记录。
type Account struct {
	Index        uint32       `json:"index"`
	Address      string       `json:"address"`
	PasswordHash PasswordHash `json:"password_hash"`
	CreatedAt    time.Time    `json:"created_at"`
}

// clone 返回一份深拷贝，让调用方拿到的记录与内部状态彻底解耦。
//
// PasswordHash 里的 Salt / Key 是切片，浅拷贝会让调用方直接改到内部数组上：
// 一份「副本」被改动后库里的验证子也跟着变，密码校验随之失效。
func (a Account) clone() Account {
	out := a
	out.PasswordHash.Salt = append([]byte(nil), a.PasswordHash.Salt...)
	out.PasswordHash.Key = append([]byte(nil), a.PasswordHash.Key...)
	return out
}

// ErrCapacity 表示账户数量已达上限（由 SetMaxAccounts 设置）。
var ErrCapacity = errors.New("store: 账户数量已达上限")

// LockoutError 表示该账户因连续密码错误被临时锁定。指数退避的延迟放在
// RetryAfter 里，调用方可用它生成 Retry-After 响应头。
type LockoutError struct{ RetryAfter time.Duration }

func (e *LockoutError) Error() string {
	return fmt.Sprintf("store: 账户因连续密码错误被临时锁定（%.0fs 后重试）", e.RetryAfter.Seconds())
}

// lockoutState 是某个账户的失败计数与锁定期限。首次失败不锁，从第二次起指数退避。
type lockoutState struct {
	failures int
	until    time.Time
}

const (
	lockoutBase = 200 * time.Millisecond
	lockoutMax  = 30 * time.Second
)

// Store 是并发安全的账户库，全部状态放在内存里，每次写入整体原子落盘。
//
// 之所以不用数据库：账户数量级不大、写入极少（只有创建账户会写），而整库落盘换来
// 的是「要么是旧的完整状态，要么是新的完整状态」这种最容易推理的持久化语义。
type Store struct {
	path   string
	params Argon2Params
	// integrityKey 用于给整库算 HMAC，由调用方从助记词派生后传入。
	integrityKey []byte

	mu          sync.RWMutex
	data        fileData
	maxAccounts uint32
	lockouts    map[uint32]lockoutState

	lockFile *os.File // flock 持有到 Close，防止两个实例互踩同一账户库
}

type fileData struct {
	Version   int       `json:"version"`
	NextIndex uint32    `json:"next_index"`
	Accounts  []Account `json:"accounts"`
	// Mac 覆盖除它自身以外的全部内容。攻击者改写密码验证子时 MAC 会失配，
	// 这正是启动护栏按地址比对发现不了的那一类篡改。
	Mac string `json:"mac"`
}

// Open 打开（必要时创建）账户库文件。
//
// integrityKey 是账户库的完整性密钥，必须由调用方从助记词派生（wallet.IntegrityKey）。
// 它不能为空：没有它账户库就是明文可改的，宿主机可以伪造任意账户的密码绑定。
func Open(path string, params Argon2Params, integrityKey []byte) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: 账户库路径不能为空")
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(integrityKey) == 0 {
		return nil, errors.New("store: 必须提供账户库完整性密钥")
	}

	s := &Store{
		path:         path,
		params:       params,
		integrityKey: append([]byte(nil), integrityKey...),
		data:         fileData{Version: fileVersion},
		lockouts:     make(map[uint32]lockoutState),
	}

	// 从这里往后锁的所有权归 s：加载失败必须调 Close 把锁还回去，否则调用方在同一
	// 进程里修好文件再 Open 会撞上自己残留的 flock（表现为「被另一个实例占用」）。
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	s.lockFile = lock
	if err := s.load(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// load 读取并校验账户库，把结果填进 s。文件不存在时保留空库（首次启动的正常路径）。
func (s *Store) load() error {
	cleanupStaleTempFiles(s.path)

	info, err := os.Stat(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("store: 读取账户库 %s 失败: %w", s.path, err)
	}

	// 文件里有密码验证子，权限必须收紧；这里只告警不拒绝启动，避免容器里
	// 因 umask 差异导致服务起不来。
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		slog.Warn("账户库文件权限过宽，建议 chmod 600", "path", s.path, "mode", fmt.Sprintf("%04o", mode))
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("store: 读取账户库 %s 失败: %w", s.path, err)
	}
	// 正常写入走「临时文件 + rename」，落盘的账号库绝不可能是 0 字节；
	// 空文件只可能是截断或误创建，按损坏处理，避免静默丢掉全部密码绑定。
	if len(raw) == 0 {
		return fmt.Errorf("store: 账户库 %s 是空文件，疑似损坏，拒绝加载", s.path)
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return fmt.Errorf("store: 解析账户库 %s 失败: %w", s.path, err)
	}
	// 先验完整性再做其他校验。顺序很重要：完整性是「这份数据是否可信」的
	// 前提，损坏性校验是在讨论一份可能已被改写的数据。
	if err := s.data.verifyMac(s.integrityKey); err != nil {
		return fmt.Errorf("store: 账户库 %s 完整性校验失败: %w", s.path, err)
	}
	if err := s.data.validate(); err != nil {
		return fmt.Errorf("store: 账户库 %s 已损坏: %w", s.path, err)
	}
	return nil
}

// acquireLock 在数据文件旁占一把排他文件锁。锁放在独立的 .lock 侧车上而不是
// 数据文件上：持久化走 rename 会替换 inode，锁在数据文件上会在第一次写入后失效。
func acquireLock(path string) (*os.File, error) {
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: 打开锁文件 %s 失败: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("store: 账户库 %s 被另一个实例占用: %w", path, err)
	}
	return lock, nil
}

// cleanupStaleTempFiles 清掉上次崩溃遗留的 .tmp-* 文件（里面是完整的账户库）。
// 调用方必须已经持有文件锁，保证不会误删另一个运行实例正在写的东西。
func cleanupStaleTempFiles(path string) {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), filepath.Base(path)+".tmp-*"))
	if err != nil {
		return
	}
	for _, m := range matches {
		if err := os.Remove(m); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("清理崩溃遗留的临时文件失败", "path", m, "error", err)
		}
	}
}

// Close 释放文件锁。进程退出时 OS 会自动释放，这里显式做是为了让测试与重启路径可控。
func (s *Store) Close() error {
	if s.lockFile == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	closeErr := s.lockFile.Close()
	s.lockFile = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func (d fileData) validate() error {
	if d.Version != fileVersion {
		return fmt.Errorf("格式版本 %d 不受支持（本程序只认 %d）", d.Version, fileVersion)
	}
	// 索引从 0 开始密集分配且从不删除，因此「切片下标 == 索引」是本文件的核心不变量。
	if uint32(len(d.Accounts)) != d.NextIndex {
		return fmt.Errorf("账户数 %d 与 next_index %d 不一致", len(d.Accounts), d.NextIndex)
	}
	for i, account := range d.Accounts {
		if account.Index != uint32(i) {
			return fmt.Errorf("第 %d 条记录的索引是 %d", i, account.Index)
		}
		if account.Address == "" {
			return fmt.Errorf("索引 %d 缺少地址", account.Index)
		}
		if err := account.PasswordHash.validate(); err != nil {
			return fmt.Errorf("索引 %d 的密码验证子无效: %w", account.Index, err)
		}
	}
	// 非空库必须带 MAC。verifyMac 已经在 load 里查过，这里再确认一次是为了让
	// validate() 自身是自足的（它也是 OpenRejectsCorruptedFile 之类测试的断言点）。
	if len(d.Accounts) > 0 && d.Mac == "" {
		return errors.New("非空账户库必须带完整性校验")
	}
	return nil
}

// SetMaxAccounts 设置账户数量上限（0 表示不限制）。用于封顶整库重写的写放大。
func (s *Store) SetMaxAccounts(n uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxAccounts = n
}

// Len 返回已创建的账户数量。
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Accounts)
}

// Get 按索引读取记录，第二个返回值表示是否存在。
//
// 返回的是深拷贝，调用方改动它不会影响库内状态。
func (s *Store) Get(index uint32) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index >= s.data.NextIndex {
		return Account{}, false
	}
	return s.data.Accounts[index].clone(), true
}

// Create 分配下一个索引，用 derive 生成地址，连同密码验证子一起落盘。
//
// 密码的 Argon2id 派生放在取锁之前做：它要花上百毫秒，不该阻塞其他请求。
func (s *Store) Create(password string, derive Deriver) (Account, error) {
	// 快速路径：已满就直接拒绝，别浪费 Argon2 的时间。
	s.mu.RLock()
	full := s.maxAccounts > 0 && uint32(len(s.data.Accounts)) >= s.maxAccounts
	s.mu.RUnlock()
	if full {
		return Account{}, ErrCapacity
	}

	hash, err := hashPassword(password, s.params)
	if err != nil {
		return Account{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 锁内复查，防止并发创建一起越过上限。
	if s.maxAccounts > 0 && uint32(len(s.data.Accounts)) >= s.maxAccounts {
		return Account{}, ErrCapacity
	}

	index := s.data.NextIndex
	address, err := derive(index)
	if err != nil {
		return Account{}, err
	}

	account := Account{
		Index:        index,
		Address:      address,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}

	// 追加到一个全新的底层数组，这样回滚只需要截断，不必依赖「浅拷贝的切片头
	// 恰好没看到新元素」这种微妙不变量。Create 本来就要整库重写，这点分配可以忽略。
	previousLen := len(s.data.Accounts)
	previousMac := s.data.Mac
	grown := make([]Account, previousLen, previousLen+1)
	copy(grown, s.data.Accounts)

	s.data.Accounts = append(grown, account)
	s.data.NextIndex = index + 1
	if err := s.persistLocked(); err != nil {
		// 落盘失败就回滚内存状态，保持与磁盘一致。
		s.data.Accounts = s.data.Accounts[:previousLen]
		s.data.NextIndex = index
		s.data.Mac = previousMac
		return Account{}, err
	}
	return account, nil
}

// VerifyAddresses 用 derive 重新派生每个账户的地址并与记录比对。
//
// 用途是在启动时确认「当前配置的助记词」与「账户库」匹配：如果换错了助记词，
// 所有地址都会变，用户资产将不可达，而且不会有任何别的报错。
func (s *Store) VerifyAddresses(derive Deriver) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, account := range s.data.Accounts {
		address, err := derive(account.Index)
		if err != nil {
			return fmt.Errorf("store: 派生索引 %d 的地址失败: %w", account.Index, err)
		}
		if address != account.Address {
			return fmt.Errorf(
				"store: 索引 %d 的地址不匹配（库里 %s，当前助记词派生 %s），"+
					"说明 TEE 启动时配置的助记词与账户库不是同一个",
				account.Index, account.Address, address)
		}
	}
	return nil
}

// VerifyPassword 校验索引对应的密码。
//
// 索引不存在与密码错误都返回 ErrUnauthorized —— 索引本身通过查询接口是公开的，
// 没必要也不应该在这里区分。索引不存在时也会跑一次等价的 Argon2，抹平响应时序，
// 不让「快 / 慢」泄露索引是否存在。
func (s *Store) VerifyPassword(index uint32, password string) error {
	account, ok := s.Get(index)
	if !ok {
		dummyVerify(password, s.params)
		return ErrUnauthorized
	}
	if retryAfter, locked := s.checkLockout(index); locked {
		// 锁定分支同样要跑等价 Argon2：否则「已锁定的存在索引」微秒级返回、
		// 「不存在的索引」毫秒级返回，时序就重新变成存在性预言机。
		dummyVerify(password, s.params)
		return &LockoutError{RetryAfter: retryAfter}
	}
	if s.hashMatches(account.PasswordHash, password) {
		s.clearLockout(index)
		s.rehashLocked(index, password)
		return nil
	}
	// 这次失败可能恰好把账户推进锁定状态：直接回 LockoutError，
	// 让调用方（和用户）立即知道要等多久，而不是等下一次请求才发现被锁。
	if retryAfter, locked := s.recordFailure(index); locked {
		return &LockoutError{RetryAfter: retryAfter}
	}
	return ErrUnauthorized
}

// hashMatches 校验密码。
//
// 用记录里自带的代价参数做派生，而不是当前配置的：这样调整配置参数时老记录仍然
// 可校验，代价差异由 rehash 逐步消化（见 rehashLocked），而不是让全库一次性失效。
//
// 参数合法性由 h.validate() 兜底（其中已含 argon2Ceiling 绝对上限），防的是
// 「篡改文件把单次校验内存顶到 1 GiB」这类资源耗尽。文件现在有 HMAC 保护，
// 且 load 阶段就逐条 validate 过，所以这里是纵深防御。
func (s *Store) hashMatches(h PasswordHash, password string) bool {
	if h.validate() != nil {
		return false
	}

	passwordBytes := []byte(password)
	defer clear(passwordBytes)
	key := argon2.IDKey(passwordBytes, h.Salt, h.Time, h.MemoryKiB, h.Threads, uint32(len(h.Key)))
	defer clear(key)
	return subtle.ConstantTimeCompare(key, h.Key) == 1
}

// rehashLocked 在密码校验成功后，把代价参数落后的记录按当前配置重新派生并落盘。
//
// 有了它，调高 Argon2 代价不需要重置所有用户的密码：每个用户下次成功登录时，
// 自己那条记录就升级了。调低配置不会再把老账户挡在门外（校验按记录自带参数走），
// 但也不会把老记录降级——只在三项代价都不低于记录时才重写，否则「登录一次
// 强度降一档」的方向是反的。
//
// 任何失败都只记日志：rehash 是优化，不是安全边界，让它把已经成功的校验翻掉
// 是本末倒置。
func (s *Store) rehashLocked(index uint32, password string) {
	s.mu.RLock()
	if index >= uint32(len(s.data.Accounts)) {
		s.mu.RUnlock()
		return
	}
	current := s.data.Accounts[index].PasswordHash
	s.mu.RUnlock()

	stronger := s.params.Time >= current.Time &&
		s.params.MemoryKiB >= current.MemoryKiB &&
		s.params.Threads >= current.Threads
	identical := s.params.Time == current.Time &&
		s.params.MemoryKiB == current.MemoryKiB && s.params.Threads == current.Threads
	if !stronger || identical {
		return
	}

	hash, err := hashPassword(password, s.params)
	if err != nil {
		slog.Error("重新派生密码验证子失败", "index", index, "error", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= uint32(len(s.data.Accounts)) {
		return
	}
	previous := s.data.Accounts[index].PasswordHash
	s.data.Accounts[index].PasswordHash = hash
	if err := s.persistLocked(); err != nil {
		s.data.Accounts[index].PasswordHash = previous
		slog.Error("升级密码验证子后落盘失败", "index", index, "error", err)
		return
	}
	slog.Info("密码验证子已升级到当前代价参数", "index", index)
}

func (s *Store) checkLockout(index uint32) (time.Duration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.lockouts[index]
	if !ok || time.Now().After(state.until) {
		return 0, false
	}
	return time.Until(state.until), true
}

// recordFailure 累加失败计数。达到阈值时设置锁定，返回锁定时长与是否已锁定。
func (s *Store) recordFailure(index uint32) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.lockouts[index]
	state.failures++
	if state.failures >= 2 {
		// 从第二次失败起指数退避：200ms、400ms、…、上限 30s。
		// 第一次失败不锁，给用户留一次输错的机会。
		delay := lockoutBase << min(uint(state.failures-2), 8)
		if delay > lockoutMax {
			delay = lockoutMax
		}
		state.until = time.Now().Add(delay)
		s.lockouts[index] = state
		return delay, true
	}
	s.lockouts[index] = state
	return 0, false
}

func (s *Store) clearLockout(index uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.lockouts, index)
}

// persistLocked 把整库原子写盘：先写同目录临时文件并 fsync，再 rename 覆盖。
// 调用方必须持有写锁。
func (s *Store) persistLocked() error {
	// 先给内存里的这份状态盖上 MAC，写出去的内容才是自洽的。
	mac, err := s.data.mac(s.integrityKey)
	if err != nil {
		return err
	}
	s.data.Mac = mac

	buf, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("store: 序列化账户库失败: %w", err)
	}
	buf = append(buf, '\n')

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName) // rename 成功后这里必然是 ENOENT，忽略即可
	}()

	if _, err := tmp.Write(buf); err != nil {
		return fmt.Errorf("store: 写入临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("store: 同步临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: 关闭临时文件失败: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store: 覆盖账户库失败: %w", err)
	}
	return syncDir(dir)
}

// syncDir 同步目录项，保证 rename 的结果本身也落盘（否则掉电可能退回旧文件）。
func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("store: 打开目录 %s 失败: %w", dir, err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("store: 同步目录 %s 失败: %w", dir, err)
	}
	return nil
}
