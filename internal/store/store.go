// Package store 持久化「账户索引 -> 密码验证子」的映射。
//
// 这里刻意只存密码验证子，不存密码、也不存任何私钥：私钥由 TEE 里的助记词在现场
// 派生，进程退出即消失。记录里额外保留一份地址，作用是给助记词做一致性护栏 ——
// 如果 TEE 启动时换了一个助记词，派生出的地址会整体改变，凭这份地址就能立刻发现。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
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

// Store 是并发安全的账户库，全部状态放在内存里，每次写入整体原子落盘。
//
// 之所以不用数据库：账户数量级不大、写入极少（只有创建账户会写），而整库落盘换来
// 的是「要么是旧的完整状态，要么是新的完整状态」这种最容易推理的持久化语义。
type Store struct {
	path   string
	params Argon2Params

	mu   sync.RWMutex
	data fileData
}

type fileData struct {
	Version   int       `json:"version"`
	NextIndex uint32    `json:"next_index"`
	Accounts  []Account `json:"accounts"`
}

// Open 打开（必要时创建）账户库文件。
func Open(path string, params Argon2Params) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: 账户库路径不能为空")
	}
	if err := params.validate(); err != nil {
		return nil, err
	}

	s := &Store{
		path:   path,
		params: params,
		data:   fileData{Version: fileVersion},
	}

	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("store: 读取账户库 %s 失败: %w", path, err)
	}

	// 文件里有密码验证子，权限必须收紧；这里只告警不拒绝启动，避免容器里
	// 因 umask 差异导致服务起不来。
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		slog.Warn("账户库文件权限过宽，建议 chmod 600", "path", path, "mode", fmt.Sprintf("%04o", mode))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("store: 读取账户库 %s 失败: %w", path, err)
	}
	if len(raw) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, fmt.Errorf("store: 解析账户库 %s 失败: %w", path, err)
	}
	if err := s.data.validate(); err != nil {
		return nil, fmt.Errorf("store: 账户库 %s 已损坏: %w", path, err)
	}
	return s, nil
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
	}
	return nil
}

// Len 返回已创建的账户数量。
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data.Accounts)
}

// Get 按索引读取记录，第二个返回值表示是否存在。
func (s *Store) Get(index uint32) (Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(index)
}

func (s *Store) getLocked(index uint32) (Account, bool) {
	if index >= s.data.NextIndex {
		return Account{}, false
	}
	return s.data.Accounts[index], true
}

// Each 按索引顺序遍历所有账户，回调必须把参数当作只读，且不得持有引用。
func (s *Store) Each(fn func(Account) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, account := range s.data.Accounts {
		if err := fn(account); err != nil {
			return err
		}
	}
	return nil
}

// Create 分配下一个索引，用 derive 生成地址，连同密码验证子一起落盘。
//
// 密码的 Argon2id 派生放在取锁之前做：它要花上百毫秒，不该阻塞其他请求。
func (s *Store) Create(password string, derive Deriver) (Account, error) {
	hash, err := hashPassword(password, s.params)
	if err != nil {
		return Account{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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

	previous := s.data
	s.data.Accounts = append(s.data.Accounts, account)
	s.data.NextIndex = index + 1
	if err := s.persistLocked(); err != nil {
		s.data = previous // 落盘失败就回滚内存状态，保持与磁盘一致
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
// 没必要也不应该在这里区分。
func (s *Store) VerifyPassword(index uint32, password string) error {
	account, ok := s.Get(index)
	if !ok || !account.PasswordHash.matches(password) {
		return ErrUnauthorized
	}
	return nil
}

// persistLocked 把整库原子写盘：先写同目录临时文件并 fsync，再 rename 覆盖。
// 调用方必须持有写锁。
func (s *Store) persistLocked() error {
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
