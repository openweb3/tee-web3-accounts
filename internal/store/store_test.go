package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fastParams 把 Argon2id 的代价压到最低，让测试跑得快；代价参数的正确性由
// TestDefaultParamsAreUsable 单独覆盖。
var fastParams = Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLength: 32}

// fakeAddress 造一个可预测的地址，让 store 完全不依赖钱包。
func fakeAddress(index uint32) (string, error) {
	return fmt.Sprintf("0x%040x", index), nil
}

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path, fastParams)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, path
}

func TestCreateAllocatesSequentialIndices(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	for i := range 3 {
		account, err := s.Create("correct horse battery", fakeAddress)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if account.Index != uint32(i) {
			t.Errorf("第 %d 个账户的索引 = %d", i, account.Index)
		}
		if account.Address != fmt.Sprintf("0x%040x", i) {
			t.Errorf("第 %d 个账户的地址 = %s", i, account.Address)
		}
		if account.PasswordHash.Algorithm != algorithmArgon2id {
			t.Errorf("密码算法 = %q", account.PasswordHash.Algorithm)
		}
		if account.CreatedAt.IsZero() {
			t.Error("创建时间未填写")
		}
	}
	if s.Len() != 3 {
		t.Errorf("Len() = %d, want 3", s.Len())
	}
}

func TestCreateDoesNotStorePlaintextPassword(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"
	s, path := openTemp(t)
	if _, err := s.Create(password, fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), password) {
		t.Fatal("账户库里出现了明文密码")
	}
}

func TestSamePasswordGetsDifferentSalt(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	first, err := s.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	second, err := s.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if string(first.PasswordHash.Salt) == string(second.PasswordHash.Salt) {
		t.Error("两次创建的盐相同，说明没有用随机盐")
	}
	if string(first.PasswordHash.Key) == string(second.PasswordHash.Key) {
		t.Error("同一密码派生出同一个验证子，说明没有加盐")
	}
}

func TestVerifyPassword(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	// 建 3 个账户：每个失败用例各用一个账户、各失败一次，避开指数退避锁定的干扰
	// （锁定行为由 TestLockoutEscalates 单独覆盖）。
	for range 3 {
		if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := s.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Errorf("正确密码被拒: %v", err)
	}
	for _, tc := range []struct {
		name     string
		index    uint32
		password string
	}{
		{"密码错误", 0, "correct horse batter"},
		{"密码为空", 1, ""},
		{"索引不存在", 7, "correct horse battery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.VerifyPassword(tc.index, tc.password)
			if !errors.Is(err, ErrUnauthorized) {
				t.Errorf("err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestPersistAndReload(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path, fastParams)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for range 2 {
		if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	// 先释放文件锁再重开，模拟真实的重启路径。
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reloaded, err := Open(path, fastParams)
	if err != nil {
		t.Fatalf("重新打开: %v", err)
	}
	if reloaded.Len() != 2 {
		t.Fatalf("重载后 Len() = %d, want 2", reloaded.Len())
	}
	if err := reloaded.VerifyPassword(1, "correct horse battery"); err != nil {
		t.Errorf("重载后校验密码失败: %v", err)
	}
	// 索引分配必须从重载后的位置继续。
	next, err := reloaded.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if next.Index != 2 {
		t.Errorf("重载后新账户索引 = %d, want 2", next.Index)
	}
}

func TestCreateFailureLeavesStoreUnchanged(t *testing.T) {
	t.Parallel()

	s, path := openTemp(t)
	expected := fmt.Errorf("派生失败")
	_, err := s.Create("correct horse battery", func(uint32) (string, error) { return "", expected })
	if !errors.Is(err, expected) {
		t.Fatalf("err = %v, want %v", err, expected)
	}
	if s.Len() != 0 {
		t.Fatalf("失败的创建污染了内存状态: Len() = %d", s.Len())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("失败的创建写了盘: %v", err)
	}

	// 索引不能被失败的创建吃掉。
	account, err := s.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if account.Index != 0 {
		t.Errorf("索引 = %d, want 0", account.Index)
	}
}

func TestVerifyAddressesDetectsMnemonicChange(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.VerifyAddresses(fakeAddress); err != nil {
		t.Errorf("地址一致时不该报错: %v", err)
	}

	err := s.VerifyAddresses(func(index uint32) (string, error) {
		return fmt.Sprintf("0xdeadbeef%036x", index), nil
	})
	if err == nil {
		t.Fatal("助记词换了却没被发现")
	}
	if !strings.Contains(err.Error(), "助记词") {
		t.Errorf("错误信息没说清原因: %v", err)
	}
}

func TestOpenRejectsCorruptedFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{"不是 JSON", "{not json"},
		{"版本不对", `{"version":99,"next_index":0,"accounts":[]}`},
		{"next_index 与账户数不一致", `{"version":1,"next_index":3,"accounts":[]}`},
		{"索引顺序错乱", `{"version":1,"next_index":1,"accounts":[{"index":5,"address":"0x1","password_hash":{"algorithm":"argon2id","time":1,"memory_kib":64,"threads":1,"salt":"c2FsdHNhbHRzYWx0c2E=","key":"a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"}}]}`},
		{"缺地址", `{"version":1,"next_index":1,"accounts":[{"index":0,"address":"","password_hash":{"algorithm":"argon2id","time":1,"memory_kib":64,"threads":1,"salt":"c2FsdHNhbHRzYWx0c2E=","key":"a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"}}]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "accounts.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := Open(path, fastParams); err == nil {
				t.Fatal("损坏的账户库被接受了")
			}
		})
	}
}

func TestOpenRejectsBadParams(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	for _, params := range []Argon2Params{
		{},
		{Time: 1, MemoryKiB: 1, Threads: 1, KeyLength: 32},
		{Time: 1, MemoryKiB: 64, Threads: 1, KeyLength: 16},
		{Time: 99, MemoryKiB: 64, Threads: 1, KeyLength: 32},
	} {
		if _, err := Open(path, params); err == nil {
			t.Errorf("%+v 应当被拒绝", params)
		}
	}
}

func TestConcurrentCreateKeepsIndicesUnique(t *testing.T) {
	t.Parallel()

	s, path := openTemp(t)

	const writers = 8
	var wg sync.WaitGroup
	created := make(chan uint32, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			account, err := s.Create("correct horse battery", fakeAddress)
			if err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			created <- account.Index
		}()
	}
	wg.Wait()
	close(created)

	seen := make(map[uint32]bool, writers)
	for index := range created {
		if seen[index] {
			t.Fatalf("索引 %d 被分配了两次", index)
		}
		seen[index] = true
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reloaded, err := Open(path, fastParams)
	if err != nil {
		t.Fatalf("重新打开: %v", err)
	}
	if reloaded.Len() != writers {
		t.Errorf("落盘后账户数 = %d, want %d", reloaded.Len(), writers)
	}
}

func TestDefaultParamsAreUsable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path, DefaultArgon2Params)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Errorf("VerifyPassword: %v", err)
	}
	if err := s.VerifyPassword(0, "wrong password"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("错误密码: %v", err)
	}
}

func TestMaxAccounts(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	defer s.Close()
	s.SetMaxAccounts(2)
	for range 2 {
		if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	if _, err := s.Create("correct horse battery", fakeAddress); !errors.Is(err, ErrCapacity) {
		t.Errorf("超过上限的创建 = %v, want ErrCapacity", err)
	}
	if s.Len() != 2 {
		t.Errorf("Len() = %d, want 2", s.Len())
	}
}

func TestLockoutEscalates(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	defer s.Close()
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var lockErr *LockoutError
	// 第一次失败不锁，只回 ErrUnauthorized。
	if err := s.VerifyPassword(0, "wrong password"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("第一次失败 err = %v", err)
	}
	// 从第二次失败起进入指数退避锁定。
	if err := s.VerifyPassword(0, "wrong password"); !errors.As(err, &lockErr) {
		t.Fatalf("第二次失败 err = %v, want LockoutError", err)
	}
	if lockErr.RetryAfter < lockoutBase || lockErr.RetryAfter > lockoutMax {
		t.Errorf("RetryAfter = %v, want 在 [%v, %v] 内", lockErr.RetryAfter, lockoutBase, lockoutMax)
	}
	// 锁定期内正确密码也拿不到，避免在线爆破绕过。
	if err := s.VerifyPassword(0, "correct horse battery"); !errors.As(err, &lockErr) {
		t.Fatalf("锁定期内 err = %v, want LockoutError", err)
	}
	// 期满后正确密码恢复。
	time.Sleep(lockErr.RetryAfter + 20*time.Millisecond)
	if err := s.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Errorf("期满后 err = %v, want nil", err)
	}
	// 成功后失败计数清零：下次再错从头算。
	if err := s.VerifyPassword(0, "wrong password"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("清零后的第一次失败 err = %v, want ErrUnauthorized", err)
	}
}

func TestOpenRejectsEmptyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s, err := Open(path, fastParams)
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Fatal("空文件被接受")
	}
}

func TestSecondOpenFailsWhileLocked(t *testing.T) {
	t.Parallel()

	s, path := openTemp(t)
	defer s.Close()
	if _, err := Open(path, fastParams); err == nil {
		t.Fatal("锁被占住时竟然能重开同一个账户库")
	}
}

func TestOpenCleansStaleTempFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	stale := filepath.Join(dir, "accounts.json.tmp-123")
	if err := os.WriteFile(stale, []byte("junk"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := Open(path, fastParams)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("崩溃遗留的临时文件没有被清理: %v", err)
	}
}

// TestHashMatchesCapsRecordedParams 覆盖 M5：记录里的代价参数不可信，
// 超过当前配置一律视为不匹配，防止篡改文件把单次校验内存顶到上限。
func TestHashMatchesCapsRecordedParams(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	defer s.Close()
	account, err := s.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !s.hashMatches(account.PasswordHash, "correct horse battery") {
		t.Error("正常记录应当匹配")
	}
	for name, mutate := range map[string]func(*PasswordHash){
		"算法":     func(h *PasswordHash) { h.Algorithm = "sha256" },
		"迭代轮数":   func(h *PasswordHash) { h.Time = 32 },
		"内存顶到上限": func(h *PasswordHash) { h.MemoryKiB = 1 << 20 },
		"并行度":    func(h *PasswordHash) { h.Threads = 64 },
	} {
		t.Run(name, func(t *testing.T) {
			h := account.PasswordHash
			mutate(&h)
			if s.hashMatches(h, "correct horse battery") {
				t.Error("被篡改的记录仍然匹配")
			}
		})
	}
}
