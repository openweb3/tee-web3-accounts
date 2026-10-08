// Package e2e 对编译出来的真实二进制做端到端验证：起进程、走 HTTP、验签名、
// 验重启后的持久化、验助记词一致性护栏。
package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openweb3/tee-web3-accounts/internal/wallet"
	"golang.org/x/crypto/argon2"
)

const (
	testMnemonic  = "test test test test test test test test test test test junk"
	otherMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	password      = "correct horse battery staple"

	// testAddress0 是 testMnemonic 在 m/44'/60'/0'/0/0 下的地址。
	testAddress0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	// testAddress1 是索引 1 的地址。
	testAddress1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
)

// binaryPath 是 TestMain 里编译出来的待测二进制。
var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tee-e2e-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "创建临时目录失败:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	binaryPath = filepath.Join(dir, "tee")
	build := exec.Command("go", "build", "-o", binaryPath, "./cmd/tee")
	build.Dir = repoRoot()
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "编译被测二进制失败:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func repoRoot() string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		panic(err)
	}
	return root
}

// --- 进程管理 ---

// lockedBuffer 是并发安全的输出缓冲：子进程的 stdout/stderr 由 exec 的内部
// goroutine 写，测试同时可能在读。
type lockedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

type server struct {
	baseURL string
	cmd     *exec.Cmd
	output  *lockedBuffer
	done    chan error

	exitedFlag bool
	exitCode   int
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// start 启动服务，等它真正开始服务后再返回。
func start(t *testing.T, mnemonic, dataFile string) *server {
	t.Helper()

	port := freePort(t)
	result := &server{
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		output:  &lockedBuffer{},
		done:    make(chan error, 1),
	}

	result.cmd = exec.Command(binaryPath)
	result.cmd.Env = append(os.Environ(),
		"TEE_MNEMONIC="+mnemonic,
		"TEE_DATA_FILE="+dataFile,
		fmt.Sprintf("TEE_LISTEN_ADDR=127.0.0.1:%d", port),
	)
	result.cmd.Stdout = result.output
	result.cmd.Stderr = result.output
	if err := result.cmd.Start(); err != nil {
		t.Fatalf("启动服务失败: %v", err)
	}
	go func() { result.done <- result.cmd.Wait() }()
	t.Cleanup(func() { result.stop(t) })

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if exited, code := result.exited(); exited {
			t.Fatalf("服务启动后退出（退出码 %d）:\n%s", code, result.output.String())
		}
		if status, _, err := result.get("/healthz"); err == nil && status == http.StatusOK {
			return result
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待服务就绪超时:\n%s", result.output.String())
	return nil
}

// exited 汇报进程是否已经结束。第一次观察到结束时会记住退出码，可以重复调用。
func (s *server) exited() (bool, int) {
	if s.exitedFlag {
		return true, s.exitCode
	}
	select {
	case err := <-s.done:
		s.exitedFlag = true
		s.exitCode = 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			s.exitCode = exitErr.ExitCode()
		} else if err != nil {
			s.exitCode = -1
		}
		return true, s.exitCode
	default:
		return false, 0
	}
}

func (s *server) stop(t *testing.T) {
	t.Helper()
	if s.exitedFlag {
		return
	}
	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		// 进程可能已经自己退出了，等 done 即可。
		<-s.done
		s.exitedFlag = true
		return
	}
	select {
	case <-s.done:
		s.exitedFlag = true
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
		s.exitedFlag = true
	}
}

// --- HTTP 辅助 ---

func (s *server) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, s.baseURL+path, reader)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}

	payload := map[string]any{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatalf("响应不是 JSON（%s %s）: %s", method, path, raw)
		}
	}
	return response.StatusCode, payload
}

func (s *server) get(path string) (int, map[string]any, error) {
	response, err := http.Get(s.baseURL + path)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	payload := map[string]any{}
	if raw, _ := io.ReadAll(response.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &payload)
	}
	return response.StatusCode, payload, nil
}

// --- 测试 ---

func TestFullFlow(t *testing.T) {
	dataFile := filepath.Join(t.TempDir(), "accounts.json")
	srv := start(t, testMnemonic, dataFile)

	t.Run("创建账户", func(t *testing.T) {
		for index, wantAddress := range []string{testAddress0, testAddress1} {
			status, payload := srv.do(t, http.MethodPost, "/v1/accounts",
				fmt.Sprintf(`{"password":%q}`, password))
			if status != http.StatusCreated {
				t.Fatalf("状态码 = %d, payload = %v", status, payload)
			}
			if payload["index"] != float64(index) {
				t.Errorf("index = %v, want %d", payload["index"], index)
			}
			if payload["address"] != wantAddress {
				t.Errorf("address = %v, want %s", payload["address"], wantAddress)
			}
			if payload["path"] != fmt.Sprintf("m/44'/60'/0'/0/%d", index) {
				t.Errorf("path = %v", payload["path"])
			}
			// 响应里绝不能出现私钥或密码。
			if strings.Contains(fmt.Sprint(payload), password) {
				t.Error("响应里出现了密码")
			}
		}
	})

	t.Run("查询地址", func(t *testing.T) {
		status, payload := srv.do(t, http.MethodGet, "/v1/accounts/1", "")
		if status != http.StatusOK {
			t.Fatalf("状态码 = %d", status)
		}
		if payload["address"] != testAddress1 {
			t.Errorf("address = %v, want %s", payload["address"], testAddress1)
		}

		if status, _ := srv.do(t, http.MethodGet, "/v1/accounts/5", ""); status != http.StatusNotFound {
			t.Errorf("越界索引状态码 = %d, want 404", status)
		}
	})

	t.Run("签名并验签", func(t *testing.T) {
		hash := sha256.Sum256([]byte("端到端签名测试"))
		hashHex := "0x" + hex.EncodeToString(hash[:])

		status, payload := srv.do(t, http.MethodPost, "/v1/sign",
			fmt.Sprintf(`{"index":0,"password":%q,"hash":%q}`, password, hashHex))
		if status != http.StatusOK {
			t.Fatalf("状态码 = %d, payload = %v", status, payload)
		}
		if payload["address"] != testAddress0 {
			t.Errorf("address = %v, want %s", payload["address"], testAddress0)
		}

		signature, err := hex.DecodeString(strings.TrimPrefix(payload["signature"].(string), "0x"))
		if err != nil {
			t.Fatalf("解码签名: %v", err)
		}
		recovered, err := wallet.RecoverAddress(hash[:], signature)
		if err != nil {
			t.Fatalf("RecoverAddress: %v", err)
		}
		if recovered != testAddress0 {
			t.Errorf("验签恢复出的地址 = %s, want %s", recovered, testAddress0)
		}
	})

	t.Run("密码错误被拒", func(t *testing.T) {
		hash := "0x" + strings.Repeat("ab", 32)
		status, payload := srv.do(t, http.MethodPost, "/v1/sign",
			fmt.Sprintf(`{"index":0,"password":"wrong password","hash":%q}`, hash))
		if status != http.StatusUnauthorized {
			t.Errorf("状态码 = %d, want 401 (payload %v)", status, payload)
		}
	})

	srv.stop(t)

	t.Run("重启后账户仍在且索引继续", func(t *testing.T) {
		restarted := start(t, testMnemonic, dataFile)
		defer restarted.stop(t)

		status, payload := restarted.do(t, http.MethodGet, "/v1/accounts/0", "")
		if status != http.StatusOK || payload["address"] != testAddress0 {
			t.Fatalf("重启后查询账户 0 失败: %d %v", status, payload)
		}

		// 老密码仍然有效。
		hash := "0x" + strings.Repeat("ab", 32)
		if status, payload := restarted.do(t, http.MethodPost, "/v1/sign",
			fmt.Sprintf(`{"index":1,"password":%q,"hash":%q}`, password, hash)); status != http.StatusOK {
			t.Errorf("重启后签名失败: %d %v", status, payload)
		}

		// 新账户的索引从 2 开始，不能覆盖已有账户。
		status, payload = restarted.do(t, http.MethodPost, "/v1/accounts",
			fmt.Sprintf(`{"password":%q}`, password))
		if status != http.StatusCreated || payload["index"] != float64(2) {
			t.Errorf("重启后创建账户: %d %v", status, payload)
		}
	})
}

// TestMnemonicMismatchIsRejected 是这套系统最重要的护栏：换错助记词必须拒绝启动，
// 否则服务会安静地派生出一整套不同的地址，用户资产将不可达。
// TestTamperedStoreIsRejected 覆盖 P0 的端到端路径：宿主机改写账户库里的密码验证子
// 后重启，真实二进制必须拒绝启动。地址保持不变，所以这条路径此前是绿的。
func TestTamperedStoreIsRejected(t *testing.T) {
	dataFile := filepath.Join(t.TempDir(), "accounts.json")

	srv := start(t, testMnemonic, dataFile)
	if status, payload := srv.do(t, http.MethodPost, "/v1/accounts",
		fmt.Sprintf(`{"password":%q}`, password)); status != http.StatusCreated {
		t.Fatalf("创建账户失败: %d %v", status, payload)
	}
	srv.stop(t)

	// 宿主机改写文件：地址原样保留，只把 password_hash 换成攻击者自选密码的派生值。
	raw, err := os.ReadFile(dataFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	accounts, _ := doc["accounts"].([]any)
	if len(accounts) != 1 {
		t.Fatalf("账户数 = %d, want 1", len(accounts))
	}
	entry, _ := accounts[0].(map[string]any)
	attackerPassword := "host-chosen-pw-1234"
	salt := []byte("hostpicked000000")
	entry["password_hash"] = map[string]any{
		"algorithm":  "argon2id",
		"time":       1,
		"memory_kib": 64,
		"threads":    1,
		"salt":       salt,
		"key": argon2.IDKey([]byte(attackerPassword), salt,
			1, 64, 1, 32),
	}
	forged, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(dataFile, forged, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// 必须拒绝启动，而不是带着伪造的密码绑定对外服务。
	cmd := exec.Command(binaryPath)
	buffer := &bytes.Buffer{}
	cmd.Env = append(os.Environ(),
		"TEE_MNEMONIC="+testMnemonic,
		"TEE_DATA_FILE="+dataFile,
		"TEE_LISTEN_ADDR=127.0.0.1:"+fmt.Sprint(freePort(t)),
	)
	cmd.Stdout, cmd.Stderr = buffer, buffer

	if err := cmd.Run(); err == nil {
		t.Fatalf("被篡改的账户库竟然启动成功了:\n%s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "完整性") {
		t.Errorf("日志里没有指出完整性校验失败:\n%s", buffer.String())
	}
}

func TestMnemonicMismatchIsRejected(t *testing.T) {
	dataFile := filepath.Join(t.TempDir(), "accounts.json")

	srv := start(t, testMnemonic, dataFile)
	if status, payload := srv.do(t, http.MethodPost, "/v1/accounts",
		fmt.Sprintf(`{"password":%q}`, password)); status != http.StatusCreated {
		t.Fatalf("创建账户失败: %d %v", status, payload)
	}
	srv.stop(t)

	// 换一个助记词再启动，必须在启动阶段就失败。
	cmd := exec.Command(binaryPath)
	buffer := &bytes.Buffer{}
	cmd.Env = append(os.Environ(),
		"TEE_MNEMONIC="+otherMnemonic,
		"TEE_DATA_FILE="+dataFile,
		"TEE_LISTEN_ADDR=127.0.0.1:"+fmt.Sprint(freePort(t)),
	)
	cmd.Stdout, cmd.Stderr = buffer, buffer

	err := cmd.Run()
	if err == nil {
		t.Fatalf("换了助记词竟然启动成功了:\n%s", buffer.String())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("期望退出码错误, got %v", err)
	}
	if !strings.Contains(buffer.String(), "助记词") {
		t.Errorf("日志里没有说明是助记词问题:\n%s", buffer.String())
	}
}

// TestVerifyPulledSignature 校验 cloudtest 从真实 TEE 实例上拉回来的签名。
//
// 实例上没有 secp256k1 库，所以远端只检查签名的格式与确定性；真正的密码学验证放在
// 这里做：用测试助记词独立重新派生期望地址，再从签名恢复地址，两者必须一致。
// 没设置 TEE_CLOUDTEST_SIGNATURE 时跳过，不影响常规 `go test ./...`。
func TestVerifyPulledSignature(t *testing.T) {
	artifact := os.Getenv("TEE_CLOUDTEST_SIGNATURE")
	if artifact == "" {
		t.Skip("未设置 TEE_CLOUDTEST_SIGNATURE，跳过 cloudtest 拉回的签名验证")
	}

	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("读取 %s: %v", artifact, err)
	}
	var payload struct {
		Index             uint32   `json:"index"`
		Hash              string   `json:"hash"`
		Address           string   `json:"address"`
		Signature         string   `json:"signature"`
		ExpectedAddresses []string `json:"expected_addresses"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("解析 %s: %v", artifact, err)
	}

	hash, err := hex.DecodeString(strings.TrimPrefix(payload.Hash, "0x"))
	if err != nil || len(hash) != 32 {
		t.Fatalf("哈希不合法（%d 字节）: %v", len(hash), err)
	}
	signature, err := hex.DecodeString(strings.TrimPrefix(payload.Signature, "0x"))
	if err != nil || len(signature) != 65 {
		t.Fatalf("签名不合法（%d 字节）: %v", len(signature), err)
	}

	// 本地用自己的实现重新派生期望地址，完全不信任远端返回的东西。
	accountWallet, err := wallet.Open(wallet.Config{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	expected, err := accountWallet.Address(payload.Index)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}

	if payload.Address != expected {
		t.Errorf("远端返回的地址 = %s, 本地派生 = %s", payload.Address, expected)
	}
	// 远端脚本里硬编码的公开已知地址也必须对上，形成三方一致。
	if int(payload.Index) < len(payload.ExpectedAddresses) {
		if want := payload.ExpectedAddresses[payload.Index]; want != expected {
			t.Errorf("远端硬编码的期望地址 = %s, 本地派生 = %s", want, expected)
		}
	}

	recovered, err := wallet.RecoverAddress(hash, signature)
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	if recovered != expected {
		t.Errorf("验签恢复出的地址 = %s, want %s", recovered, expected)
	}
}

// TestMissingMnemonicIsRejected 确认没有配助记词时不会退回任何默认种子。
func TestMissingMnemonicIsRejected(t *testing.T) {
	cmd := exec.Command(binaryPath)
	buffer := &bytes.Buffer{}
	// 只保留无关环境变量，确保 TEE_MNEMONIC 一定不存在。
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	cmd.Stdout, cmd.Stderr = buffer, buffer

	if err := cmd.Run(); err == nil {
		t.Fatalf("没配助记词竟然启动成功了:\n%s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "TEE_MNEMONIC") {
		t.Errorf("日志里没有指明缺少哪个配置:\n%s", buffer.String())
	}
}

// TestInvalidMnemonicIsRejected 确认助记词校验和能拦住打错的助记词。
func TestInvalidMnemonicIsRejected(t *testing.T) {
	// 把 junk 换成另一个词表内的词，校验和必然不匹配。
	broken := strings.Replace(testMnemonic, "junk", "zoo", 1)

	cmd := exec.Command(binaryPath)
	buffer := &bytes.Buffer{}
	cmd.Env = append(os.Environ(),
		"TEE_MNEMONIC="+broken,
		"TEE_DATA_FILE="+filepath.Join(t.TempDir(), "accounts.json"),
		"TEE_LISTEN_ADDR=127.0.0.1:"+fmt.Sprint(freePort(t)),
	)
	cmd.Stdout, cmd.Stderr = buffer, buffer

	if err := cmd.Run(); err == nil {
		t.Fatalf("非法助记词竟然启动成功了:\n%s", buffer.String())
	}
	if !strings.Contains(buffer.String(), "校验和") {
		t.Errorf("日志里没有说明是校验和问题:\n%s", buffer.String())
	}
}
