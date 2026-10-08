package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// fastParams 把 Argon2id 的代价压到最低，让测试跑得快；代价参数的正确性由
// TestDefaultParamsAreUsable 单独覆盖。
var fastParams = Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLength: 32}

// testIntegrityKey 是测试用的完整性密钥。真实运行时它由助记词派生，
// 测试不需要真的走一遍 BIP-39。
var testIntegrityKey = []byte("test-integrity-key-32byte")

// wrongIntegrityKey 用于模拟「换了助记词」或「攻击者伪造」的情况。
var wrongIntegrityKey = []byte("attacker-key-32-bytes-long")

// fakeAddress 造一个可预测的地址，让 store 完全不依赖钱包。
func fakeAddress(index uint32) (string, error) {
	return fmt.Sprintf("0x%040x", index), nil
}

// signAndMarshal 给 data 盖上合法 MAC 后序列化。落盘的账户库一律带 MAC，
// 所以「内容损坏但完整性合法」的样本必须经这里构造，否则会先被完整性校验拦下，
// 测不到本来想测的分支。
func signAndMarshal(t *testing.T, data fileData) string {
	t.Helper()
	mac, err := data.mac(testIntegrityKey)
	if err != nil {
		t.Fatalf("mac: %v", err)
	}
	data.Mac = mac
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(raw)
}

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path, fastParams, testIntegrityKey)
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
	s, err := Open(path, fastParams, testIntegrityKey)
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

	reloaded, err := Open(path, fastParams, testIntegrityKey)
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

	// 这些样本都刻意保持「结构上损坏」，且全部配合法 MAC（落盘的库一律带 MAC），
	// 否则它们会先在完整性校验上被拦下，测不到本来想测的那条分支。
	validHash := PasswordHash{
		Algorithm: algorithmArgon2id, Time: 1, MemoryKiB: 64, Threads: 1,
		Salt: []byte("saltsaltsaltsalt"), Key: []byte("keykeykeykeykeykeykeykeykeykeykeyke"),
	}

	tests := []struct {
		name    string
		content string
	}{
		{"不是 JSON", "{not json"},
		{"版本不对", signAndMarshal(t, fileData{Version: 99})},
		{"next_index 与账户数不一致", signAndMarshal(t, fileData{Version: fileVersion, NextIndex: 3})},
		{"索引顺序错乱", signAndMarshal(t, fileData{Version: fileVersion, NextIndex: 1,
			Accounts: []Account{{Index: 5, Address: "0x1", PasswordHash: validHash}}})},
		{"缺地址", signAndMarshal(t, fileData{Version: fileVersion, NextIndex: 1,
			Accounts: []Account{{Index: 0, Address: "", PasswordHash: validHash}}})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "accounts.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := Open(path, fastParams, testIntegrityKey); err == nil {
				t.Fatal("损坏的账户库被接受了")
			}
		})
	}
}

// TestOpenRejectsForgedPasswordBinding 是 P0 的回归测试：宿主机改写密码验证子后，
// 即使把地址原样保留（骗过地址护栏），也必须因为 MAC 失配而被拒。
func TestOpenRejectsForgedPasswordBinding(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")

	realAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	s, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Create("victim-strong-password", func(uint32) (string, error) {
		return realAddress, nil
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 宿主机改写文件：地址保持真实，只把密码验证子换成攻击者自选密码的派生值。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var forged fileData
	if err := json.Unmarshal(raw, &forged); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	attackerPassword := "host-chosen-pw-1234"
	forgedSalt := []byte("hostpicked000000")
	forged.Accounts[0].PasswordHash = PasswordHash{
		Algorithm: algorithmArgon2id, Time: 1, MemoryKiB: 64, Threads: 1,
		Salt: forgedSalt,
		Key:  argon2.IDKey([]byte(attackerPassword), forgedSalt, 1, 64, 1, 32),
	}
	out, err := json.MarshalIndent(forged, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// 重启必须失败。加载阶段就该拦住，而不是等到有人来签名。
	reopened, err := Open(path, fastParams, testIntegrityKey)
	if err == nil {
		reopened.Close()
		t.Fatal("被伪造的账户库竟然加载成功了")
	}
	if !strings.Contains(err.Error(), "完整性") {
		t.Errorf("错误信息应指向完整性校验失败，实际是: %v", err)
	}
}

// TestOpenRejectsWrongIntegrityKey 确认换一把密钥就打不开：MAC 必须真的绑到助记词上，
// 否则「用错误的密钥」和「没有密钥」就区分不开了。
func TestOpenRejectsWrongIntegrityKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if reopened, err := Open(path, fastParams, wrongIntegrityKey); err == nil {
		reopened.Close()
		t.Fatal("换一把密钥竟然也能打开")
	}
	// 正确密钥仍然打得开。
	reopened, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("用原密钥重开失败: %v", err)
	}
	defer reopened.Close()
	if err := reopened.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Errorf("重开后校验失败: %v", err)
	}
}

func TestOpenRejectsMissingIntegrityKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	if _, err := Open(path, fastParams, nil); err == nil {
		t.Fatal("没有完整性密钥却接受了启动")
	}
}

// TestGetReturnsDeepCopy 确认调用方拿到的是副本：改副本不会污染库内状态。
func TestGetReturnsDeepCopy(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	defer s.Close()
	created, err := s.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, ok := s.Get(created.Index)
	if !ok {
		t.Fatal("Get 返回不存在")
	}
	got.Address = "0xdeadbeef"
	got.PasswordHash.Key[0] ^= 0xFF

	again, _ := s.Get(created.Index)
	if again.Address != created.Address {
		t.Errorf("改副本后地址被污染: %s", again.Address)
	}
	if again.PasswordHash.Key[0] != created.PasswordHash.Key[0] {
		t.Error("改副本后密码验证子被污染")
	}
	if err := s.VerifyPassword(created.Index, "correct horse battery"); err != nil {
		t.Errorf("改副本后正确密码被拒: %v", err)
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
		if _, err := Open(path, params, testIntegrityKey); err == nil {
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

	reloaded, err := Open(path, fastParams, testIntegrityKey)
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
	s, err := Open(path, DefaultArgon2Params, testIntegrityKey)
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
	s, err := Open(path, fastParams, testIntegrityKey)
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Fatal("空文件被接受")
	}
}

// TestOpenRejectsUnsignedEmptyFile 覆盖 P0 的回归：宿主机把账户库回滚成一行
// 手工构造的空库（无 MAC），必须被拒绝，而不是带着空库启动后从索引 0 重新分配、
// 让攻击者用自选密码劫持原受害者的地址。合法写出的空库（带 MAC）仍可加载。
func TestOpenRejectsUnsignedEmptyFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")

	if err := os.WriteFile(path, []byte(`{"version":1,"next_index":0,"accounts":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if s, err := Open(path, fastParams, testIntegrityKey); err == nil {
		s.Close()
		t.Fatal("无 MAC 的空库竟然被接受")
	}

	// 同一份空库，盖上合法 MAC 后必须能正常打开（首写前的空库也是合法状态）。
	// 注意 Accounts 必须是空切片而非 nil，序列化结果才与 `[]` 一致。
	content := signAndMarshal(t, fileData{Version: fileVersion, Accounts: []Account{}})
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("带合法 MAC 的空库应当可以打开: %v", err)
	}
	defer s.Close()
	if s.Len() != 0 {
		t.Errorf("Len() = %d, want 0", s.Len())
	}
}

func TestSecondOpenFailsWhileLocked(t *testing.T) {
	t.Parallel()

	s, path := openTemp(t)
	defer s.Close()
	if _, err := Open(path, fastParams, testIntegrityKey); err == nil {
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

	s, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("崩溃遗留的临时文件没有被清理: %v", err)
	}
}

func TestOpenReleasesLockOnLoadFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := Open(path, fastParams, testIntegrityKey); err == nil {
		t.Fatal("损坏的账户库本该被拒绝")
	}

	// 失败路径必须把锁还回去，否则修好文件后重开会撞上自己残留的 flock。
	// 「修好」意味着内容与 MAC 都合法，所以要用 signAndMarshal 构造。
	if err := os.WriteFile(path, []byte(signAndMarshal(t, fileData{Version: fileVersion})), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("加载失败后重开被残留的文件锁挡住了: %v", err)
	}
	defer s.Close()
}

// TestVerifyPasswordSurvivesParamDowngrade 覆盖 P1：以前调低配置会让全库老账户
// 永久无法签名（h.Time > s.params.Time 成立即视为不匹配），且没有任何自愈路径。
// 现在校验按记录自带参数走，改配置不会再把用户挡在门外。
func TestVerifyPasswordSurvivesParamDowngrade(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	strong := Argon2Params{Time: 3, MemoryKiB: 512, Threads: 2, KeyLength: 32}
	s, err := Open(path, strong, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 运维把配置调低到比存量记录更弱的参数。
	weaker := Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLength: 32}
	downgraded, err := Open(path, weaker, testIntegrityKey)
	if err != nil {
		t.Fatalf("降配后打开失败: %v", err)
	}
	defer downgraded.Close()
	if err := downgraded.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Fatalf("降配后正确密码被拒: %v", err)
	}
	if err := downgraded.VerifyPassword(0, "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("降配后错误密码居然通过: %v", err)
	}
}

// TestVerifyPasswordRehashesToCurrentParams 确认成功校验会把落后的记录升级到当前参数，
// 因此调高代价不需要重置所有用户的密码。
func TestVerifyPasswordRehashesToCurrentParams(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	weak := Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLength: 32}
	s, err := Open(path, weak, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	stronger := Argon2Params{Time: 2, MemoryKiB: 128, Threads: 2, KeyLength: 32}
	upgraded, err := Open(path, stronger, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	before, _ := upgraded.Get(0)
	if before.PasswordHash.Time != 1 {
		t.Fatalf("前置条件不成立: 记录 Time = %d", before.PasswordHash.Time)
	}

	if err := upgraded.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	after, _ := upgraded.Get(0)
	if after.PasswordHash.Time != stronger.Time ||
		after.PasswordHash.MemoryKiB != stronger.MemoryKiB ||
		after.PasswordHash.Threads != stronger.Threads {
		t.Errorf("rehash 未生效: t=%d m=%d p=%d",
			after.PasswordHash.Time, after.PasswordHash.MemoryKiB, after.PasswordHash.Threads)
	}
	// 升级后的验证子必须仍然对应同一个密码，且落盘后能重开。
	if err := upgraded.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Errorf("rehash 后校验失败: %v", err)
	}
	if err := upgraded.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	reopened, err := Open(path, stronger, testIntegrityKey)
	if err != nil {
		t.Fatalf("rehash 后重开失败: %v", err)
	}
	defer reopened.Close()
	if err := reopened.VerifyPassword(0, "correct horse battery"); err != nil {
		t.Errorf("重开后校验失败: %v", err)
	}
}

// TestHashMatchesRejectsParamsAboveCeiling 确认绝对上限仍然生效：即使密钥泄露，
// 一条记录也不能把单次校验顶到 1 GiB。
func TestHashMatchesRejectsParamsAboveCeiling(t *testing.T) {
	t.Parallel()

	s, _ := openTemp(t)
	defer s.Close()
	account, err := s.Create("correct horse battery", fakeAddress)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for name, mutate := range map[string]func(*PasswordHash){
		"迭代轮数超上限": func(h *PasswordHash) { h.Time = argon2Ceiling.Time + 1 },
		"内存超上限":   func(h *PasswordHash) { h.MemoryKiB = argon2Ceiling.MemoryKiB + 1 },
		"并行度超上限":  func(h *PasswordHash) { h.Threads = argon2Ceiling.Threads + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			h := account.PasswordHash
			mutate(&h)
			if s.hashMatches(h, "correct horse battery") {
				t.Error("超过绝对上限的记录竟然匹配了")
			}
		})
	}
}

// TestMacValidButAddressWrongStillCaught 覆盖完整性校验通过、但地址对不上的情形。
//
// 这是两道护栏的分工：HMAC 挡「宿主机改了文件」，地址比对挡「文件没被改，
// 但记录本身与当前助记词不符」。这里模拟攻击者连 MAC 密钥一起掌握的情况
// （文件被改且 MAC 合法），确认地址护栏仍会独立报警。
func TestMacValidButAddressWrongStillCaught(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := s.Create("correct horse battery", fakeAddress); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 读出来改地址，再用同一个密钥重算 MAC —— 完整性校验会通过。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var doc fileData
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	doc.Accounts[0].Address = "0x000000000000000000000000000000000000dEaD"
	mac, err := doc.mac(testIntegrityKey)
	if err != nil {
		t.Fatalf("mac: %v", err)
	}
	doc.Mac = mac
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	reopened, err := Open(path, fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("MAC 合法时应当能打开: %v", err)
	}
	defer reopened.Close()

	// 完整性过了，但地址护栏必须独立发现不一致。
	err = reopened.VerifyAddresses(fakeAddress)
	if err == nil {
		t.Fatal("地址已被换掉却没有被发现")
	}
	if !strings.Contains(err.Error(), "助记词") {
		t.Errorf("错误信息应指向助记词不匹配: %v", err)
	}
}
