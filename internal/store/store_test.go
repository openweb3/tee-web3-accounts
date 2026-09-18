package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
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
		{"密码为空", 0, ""},
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

	reloaded, err := Open(path, fastParams)
	if err != nil {
		t.Fatalf("重新打开: %v", err)
	}
	if reloaded.Len() != writers {
		t.Errorf("落盘后账户数 = %d, want %d", reloaded.Len(), writers)
	}
}

func TestEachVisitsEveryAccountInOrder(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	for range 3 {
		if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	var indices []uint32
	if err := s.Each(func(account Account) error {
		indices = append(indices, account.Index)
		return nil
	}); err != nil {
		t.Fatalf("Each: %v", err)
	}
	if fmt.Sprint(indices) != "[0 1 2]" {
		t.Errorf("遍历顺序 = %v", indices)
	}

	stop := errors.New("停")
	if err := s.Each(func(Account) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("Each 应当透传回调错误, got %v", err)
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
