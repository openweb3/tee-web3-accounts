package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openweb3/tee-web3-accounts/internal/store"
	"github.com/openweb3/tee-web3-accounts/internal/wallet"
)

const (
	testMnemonic = "test test test test test test test test test test test junk"
	testPassword = "correct horse battery staple"
)

// testAddresses 是 testMnemonic 在 m/44'/60'/0'/0/{i} 下的地址。
var testAddresses = []string{
	"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
	"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
}

// fastParams 压低 Argon2id 代价，让接口测试跑得快。
var fastParams = store.Argon2Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLength: 32}

// testIntegrityKey 是 store 完整性密钥的测试替身，真实运行时由助记词派生。
var testIntegrityKey = []byte("api-test-integrity-key-32b")

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()

	accountWallet, err := wallet.Open(wallet.Config{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	accountStore, err := store.Open(filepath.Join(t.TempDir(), "accounts.json"), fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	server, err := New(Config{Wallet: accountWallet, Store: accountStore})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return server.Handler()
}

// request 发一次请求并返回状态码与原始响应体。
func request(t *testing.T, handler http.Handler, method, path, body string) (int, string, http.Header) {
	t.Helper()

	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder.Code, recorder.Body.String(), recorder.Result().Header
}

// decode 把响应体解析成 map，方便断言字段。
func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("解析响应 %q 失败: %v", raw, err)
	}
	return payload
}

// createAccount 建一个账户，断言创建成功。
func createAccount(t *testing.T, handler http.Handler) {
	t.Helper()
	status, body, _ := request(t, handler, http.MethodPost, "/v1/accounts",
		fmt.Sprintf(`{"password":%q}`, testPassword))
	if status != http.StatusCreated {
		t.Fatalf("创建账户状态码 = %d, body = %s", status, body)
	}
}

func TestHealth(t *testing.T) {
	t.Parallel()

	status, body, _ := request(t, newTestHandler(t), http.MethodGet, "/healthz", "")
	if status != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", status, body)
	}
	if decode(t, body)["status"] != "ok" {
		t.Errorf("body = %s", body)
	}
}

func TestCreateAccountReturnsDerivedAddress(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	for index, wantAddress := range testAddresses {
		status, body, header := request(t, handler, http.MethodPost, "/v1/accounts",
			fmt.Sprintf(`{"password":%q}`, testPassword))
		if status != http.StatusCreated {
			t.Fatalf("状态码 = %d, body = %s", status, body)
		}
		if got := header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q", got)
		}

		payload := decode(t, body)
		if got := payload["address"]; got != wantAddress {
			t.Errorf("index %d 地址 = %v, want %s", index, got, wantAddress)
		}
		if got := payload["index"]; got != float64(index) {
			t.Errorf("index = %v, want %d", got, index)
		}
		if got := payload["path"]; got != fmt.Sprintf("m/44'/60'/0'/0/%d", index) {
			t.Errorf("path = %v", got)
		}
		assertExactKeys(t, payload, "index", "path", "address")
	}
}

func TestCreateAccountValidatesPassword(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	for _, password := range []string{"", "short", strings.Repeat("a", MaxPasswordLength+1)} {
		status, body, _ := request(t, handler, http.MethodPost, "/v1/accounts",
			fmt.Sprintf(`{"password":%q}`, password))
		if status != http.StatusBadRequest {
			t.Errorf("密码长度 %d 的状态码 = %d, want 400 (body %s)", len(password), status, body)
		}
	}
}

func TestCreateAccountRejectsMalformedBody(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	tests := []struct {
		name string
		body string
	}{
		{"不是 JSON", `{`},
		{"未知字段", fmt.Sprintf(`{"password":%q,"admin":true}`, testPassword)},
		{"多个对象", fmt.Sprintf(`{"password":%q}{"password":%q}`, testPassword, testPassword)},
		{"超大请求体", fmt.Sprintf(`{"password":%q}`, strings.Repeat("a", maxRequestBodyBytes+1))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, body, _ := request(t, handler, http.MethodPost, "/v1/accounts", tc.body)
			if status != http.StatusBadRequest {
				t.Errorf("状态码 = %d, want 400 (body %s)", status, body)
			}
		})
	}
}

func TestGetAccount(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	createAccount(t, handler)
	createAccount(t, handler)

	status, body, _ := request(t, handler, http.MethodGet, "/v1/accounts/1", "")
	if status != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", status, body)
	}
	payload := decode(t, body)
	if payload["address"] != testAddresses[1] {
		t.Errorf("address = %v, want %s", payload["address"], testAddresses[1])
	}
	assertExactKeys(t, payload, "index", "path", "address")

	for _, path := range []string{"/v1/accounts/2", "/v1/accounts/999"} {
		status, body, _ := request(t, handler, http.MethodGet, path, "")
		if status != http.StatusNotFound {
			t.Errorf("%s 状态码 = %d, want 404 (body %s)", path, status, body)
		}
	}

	for _, path := range []string{"/v1/accounts/abc", "/v1/accounts/-1"} {
		status, _, _ := request(t, handler, http.MethodGet, path, "")
		if status != http.StatusBadRequest {
			t.Errorf("%s 状态码 = %d, want 400", path, status)
		}
	}
}

// TestGetAccountNeedsNoPassword 明确：查询地址是公开操作。
func TestGetAccountNeedsNoPassword(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	createAccount(t, handler)

	status, body, _ := request(t, handler, http.MethodGet, "/v1/accounts/0", "")
	if status != http.StatusOK {
		t.Fatalf("查询地址不该需要密码，状态码 = %d, body = %s", status, body)
	}
}

func TestSign(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	createAccount(t, handler)

	hash := "0x" + strings.Repeat("ab", 32)
	status, body, _ := request(t, handler, http.MethodPost, "/v1/sign",
		fmt.Sprintf(`{"index":0,"password":%q,"hash":%q}`, testPassword, hash))
	if status != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", status, body)
	}

	payload := decode(t, body)
	assertExactKeys(t, payload, "index", "path", "address", "hash", "signature")
	if payload["address"] != testAddresses[0] {
		t.Errorf("address = %v, want %s", payload["address"], testAddresses[0])
	}

	// 用签名反推地址，必须回到同一个账户 —— 这是对签名正确性最直接的自检。
	rawHash, err := hex.DecodeString(strings.TrimPrefix(hash, "0x"))
	if err != nil {
		t.Fatalf("解码 hash: %v", err)
	}
	rawSignature, err := hex.DecodeString(strings.TrimPrefix(payload["signature"].(string), "0x"))
	if err != nil {
		t.Fatalf("解码 signature: %v", err)
	}
	recovered, err := wallet.RecoverAddress(rawHash, rawSignature)
	if err != nil {
		t.Fatalf("RecoverAddress: %v", err)
	}
	if recovered != testAddresses[0] {
		t.Errorf("恢复出的地址 = %s, want %s", recovered, testAddresses[0])
	}
	if payload["hash"] != hash {
		t.Errorf("回显的 hash = %v, want %s", payload["hash"], hash)
	}
}

// TestSignAcceptsBareHash 确认不带 0x 前缀的哈希也能用。
func TestSignAcceptsBareHash(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	createAccount(t, handler)

	body := fmt.Sprintf(`{"index":0,"password":%q,"hash":%q}`, testPassword, strings.Repeat("cd", 32))
	status, response, _ := request(t, handler, http.MethodPost, "/v1/sign", body)
	if status != http.StatusOK {
		t.Fatalf("状态码 = %d, body = %s", status, response)
	}
	if got := decode(t, response)["hash"]; got != "0x"+strings.Repeat("cd", 32) {
		t.Errorf("hash = %v", got)
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	createAccount(t, handler)

	validHash := strings.Repeat("ab", 32)
	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"密码错误", fmt.Sprintf(`{"index":0,"password":"wrong password","hash":%q}`, validHash), http.StatusUnauthorized},
		{"密码为空", fmt.Sprintf(`{"index":0,"password":"","hash":%q}`, validHash), http.StatusUnauthorized},
		{"索引不存在", fmt.Sprintf(`{"index":9,"password":%q,"hash":%q}`, testPassword, validHash), http.StatusUnauthorized},
		{"hash 太短", fmt.Sprintf(`{"index":0,"password":%q,"hash":"0xabcd"}`, testPassword), http.StatusBadRequest},
		{"hash 不是十六进制", fmt.Sprintf(`{"index":0,"password":%q,"hash":%q}`, testPassword, strings.Repeat("zz", 32)), http.StatusBadRequest},
		{"缺 hash", fmt.Sprintf(`{"index":0,"password":%q}`, testPassword), http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			status, body, _ := request(t, handler, http.MethodPost, "/v1/sign", tc.body)
			if status != tc.wantStatus {
				t.Errorf("状态码 = %d, want %d (body %s)", status, tc.wantStatus, body)
			}
			// 错误响应不能泄露密码或内部细节。
			if strings.Contains(body, testPassword) {
				t.Errorf("错误响应里出现了密码: %s", body)
			}
		})
	}
}

// TestSignWrongPasswordDoesNotRevealIndexExistence 确认「索引不存在」与「密码错误」
// 返回完全一样的响应，不给出探测信号。
func TestSignWrongPasswordDoesNotRevealIndexExistence(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	createAccount(t, handler)

	validHash := strings.Repeat("ab", 32)
	wrongPasswordBody := fmt.Sprintf(`{"index":0,"password":"wrong password","hash":%q}`, validHash)
	missingIndexBody := fmt.Sprintf(`{"index":42,"password":"wrong password","hash":%q}`, validHash)

	firstStatus, firstBody, _ := request(t, handler, http.MethodPost, "/v1/sign", wrongPasswordBody)
	secondStatus, secondBody, _ := request(t, handler, http.MethodPost, "/v1/sign", missingIndexBody)

	if firstStatus != http.StatusUnauthorized || secondStatus != http.StatusUnauthorized {
		t.Fatalf("状态码 = %d / %d, want 401 / 401", firstStatus, secondStatus)
	}
	if firstBody != secondBody {
		t.Errorf("两种失败的响应体不同:\n%s\n%s", firstBody, secondBody)
	}
}

// TestPasswordKeyedByIndex 记录当前语义：密码策略是「每个账户一份」，
// 不同账户可以使用同一个密码，各自独立校验。
func TestPasswordKeyedByIndex(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	for _, password := range []string{"first-account-password", "second-account-passwd"} {
		status, body, _ := request(t, handler, http.MethodPost, "/v1/accounts",
			fmt.Sprintf(`{"password":%q}`, password))
		if status != http.StatusCreated {
			t.Fatalf("状态码 = %d, body = %s", status, body)
		}
	}

	hash := strings.Repeat("ab", 32)
	// 账户 0 的密码不能用来签账户 1。
	body := fmt.Sprintf(`{"index":1,"password":"first-account-password","hash":%q}`, hash)
	if status, response, _ := request(t, handler, http.MethodPost, "/v1/sign", body); status != http.StatusUnauthorized {
		t.Errorf("跨账户密码状态码 = %d, want 401 (body %s)", status, response)
	}
	// 各自用自己的密码才通。
	body = fmt.Sprintf(`{"index":1,"password":"second-account-passwd","hash":%q}`, hash)
	if status, response, _ := request(t, handler, http.MethodPost, "/v1/sign", body); status != http.StatusOK {
		t.Errorf("正确密码状态码 = %d, body = %s", status, response)
	}
}

func TestUnlockBackpressure(t *testing.T) {
	t.Parallel()

	accountWallet, err := wallet.Open(wallet.Config{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	accountStore, err := store.Open(filepath.Join(t.TempDir(), "accounts.json"), fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	server, err := New(Config{Wallet: accountWallet, Store: accountStore, MaxConcurrentUnlocks: 1})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	// 签名与创建分池：签名通道打满只影响签名，创建通道打满只影响创建。
	validHash := strings.Repeat("ab", 32)

	server.unlocks <- struct{}{}
	status, body, header := request(t, server.Handler(), http.MethodPost, "/v1/sign",
		fmt.Sprintf(`{"index":0,"password":%q,"hash":%q}`, testPassword, validHash))
	if status != http.StatusServiceUnavailable {
		t.Fatalf("签名通道打满时状态码 = %d, want 503 (body %s)", status, body)
	}
	if header.Get("Retry-After") == "" {
		t.Error("503 响应缺少 Retry-After")
	}
	// 签名通道打满不影响创建（创建走自己的池）。
	createAccount(t, server.Handler())
	<-server.unlocks

	for range cap(server.creates) {
		server.creates <- struct{}{}
	}
	status, body, header = request(t, server.Handler(), http.MethodPost, "/v1/accounts",
		fmt.Sprintf(`{"password":%q}`, testPassword))
	if status != http.StatusServiceUnavailable {
		t.Fatalf("创建通道打满时状态码 = %d, want 503 (body %s)", status, body)
	}
	if header.Get("Retry-After") == "" {
		t.Error("503 响应缺少 Retry-After")
	}
	for range cap(server.creates) {
		<-server.creates
	}
	createAccount(t, server.Handler())
}

func TestCreateRequiresAdminToken(t *testing.T) {
	t.Parallel()

	accountWallet, err := wallet.Open(wallet.Config{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	accountStore, err := store.Open(filepath.Join(t.TempDir(), "accounts.json"), fastParams, testIntegrityKey)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	server, err := New(Config{Wallet: accountWallet, Store: accountStore, AdminToken: "secret"})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	handler := server.Handler()

	create := func(auth string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/accounts",
			bytes.NewReader([]byte(fmt.Sprintf(`{"password":%q}`, testPassword))))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code, recorder.Body.String()
	}

	// 无凭据、错误 token 都被拒。
	if status, body := create(""); status != http.StatusUnauthorized {
		t.Errorf("无凭据状态码 = %d, want 401 (body %s)", status, body)
	}
	if status, body := create("Bearer wrong"); status != http.StatusUnauthorized {
		t.Errorf("错误 token 状态码 = %d, want 401 (body %s)", status, body)
	}
	// 正确 token 放行。
	if status, body := create("Bearer secret"); status != http.StatusCreated {
		t.Errorf("正确 token 状态码 = %d, want 201 (body %s)", status, body)
	}

	// 签名接口不受 admin token 约束，只认账户密码。
	hash := strings.Repeat("ab", 32)
	status, body, _ := request(t, handler, http.MethodPost, "/v1/sign",
		fmt.Sprintf(`{"index":0,"password":%q,"hash":%q}`, testPassword, hash))
	if status != http.StatusOK {
		t.Errorf("不带 token 签名状态码 = %d, want 200 (body %s)", status, body)
	}
}

func TestRoutingRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/accounts"},
		{http.MethodDelete, "/v1/accounts/0"},
		{http.MethodGet, "/v1/sign"},
	} {
		status, _, _ := request(t, handler, tc.method, tc.path, "")
		if status != http.StatusMethodNotAllowed {
			t.Errorf("%s %s 状态码 = %d, want 405", tc.method, tc.path, status)
		}
	}
}

// assertExactKeys 断言响应体恰好包含这些字段，多一个少一个都算失败 ——
// 这是「响应里不会夹带私钥」这类性质最省事的守门测试。
func assertExactKeys(t *testing.T, payload map[string]any, keys ...string) {
	t.Helper()

	want := make(map[string]bool, len(keys))
	for _, key := range keys {
		want[key] = true
	}
	for key := range payload {
		if !want[key] {
			t.Errorf("响应里出现了预期外的字段 %q", key)
		}
	}
	for key := range want {
		if _, ok := payload[key]; !ok {
			t.Errorf("响应缺少字段 %q", key)
		}
	}
}
