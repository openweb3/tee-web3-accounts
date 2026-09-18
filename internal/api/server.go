// Package api 把钱包和账户库暴露成 HTTP 接口。
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/openweb3/tee-web3-accounts/internal/store"
	"github.com/openweb3/tee-web3-accounts/internal/wallet"
)

// maxRequestBodyBytes 限制请求体大小：三个接口的入参都是短字符串，8 KiB 绰绰有余。
const maxRequestBodyBytes = 8 << 10

// Config 是构造 API 服务所需的依赖。
type Config struct {
	Wallet *wallet.Wallet
	Store  *store.Store
	// AdminToken 可选。设置后创建账户必须带 Authorization: Bearer <token>；
	// 不设置时创建接口保持开放（向后兼容，也便于本地开发）。签名接口不受它约束，
	// 签名只认账户密码。
	AdminToken string
	// MaxConcurrentUnlocks 限制同时进行的密码校验数量。
	//
	// 每次校验都要分配 64 MiB 内存做 Argon2id，不设上限的话并发请求会把 TEE 打爆；
	// 这里是硬上限，超出直接回 503，用明确的背压代替排队。
	// 留空或为 0 时使用 DefaultMaxConcurrentUnlocks。
	MaxConcurrentUnlocks int
}

// DefaultMaxConcurrentUnlocks 是默认的并发密码校验上限。
const DefaultMaxConcurrentUnlocks = 4

// DefaultMaxConcurrentCreates 是创建账户的并发上限。创建也要跑 Argon2 且会写盘，
// 但与签名分开设池，避免无凭据的创建请求把签名接口饿死。
const DefaultMaxConcurrentCreates = 2

// Server 实现三个核心接口。
type Server struct {
	wallet     *wallet.Wallet
	store      *store.Store
	adminToken string
	unlocks    chan struct{}
	creates    chan struct{}
}

// New 校验依赖并构造服务。
func New(cfg Config) (*Server, error) {
	if cfg.Wallet == nil {
		return nil, errors.New("api: 缺少 wallet")
	}
	if cfg.Store == nil {
		return nil, errors.New("api: 缺少 store")
	}

	limit := cfg.MaxConcurrentUnlocks
	if limit <= 0 {
		limit = DefaultMaxConcurrentUnlocks
	}
	return &Server{
		wallet:     cfg.Wallet,
		store:      cfg.Store,
		adminToken: cfg.AdminToken,
		unlocks:    make(chan struct{}, limit),
		creates:    make(chan struct{}, DefaultMaxConcurrentCreates),
	}, nil
}

// Handler 返回挂好路由和中间件的 HTTP 处理器。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/accounts", s.handleCreateAccount)
	mux.HandleFunc("GET /v1/accounts/{index}", s.handleGetAccount)
	mux.HandleFunc("POST /v1/sign", s.handleSign)

	return recoverPanic(logRequests(mux))
}

// tryAcquire 尝试占用一个并发名额，拿不到就立刻返回 false（不排队）。
func tryAcquire(slots chan struct{}) (release func(), ok bool) {
	select {
	case slots <- struct{}{}:
		return func() { <-slots }, true
	default:
		return nil, false
	}
}

// --- 请求/响应 ---

type createAccountRequest struct {
	Password string `json:"password"`
}

type accountResponse struct {
	Index   uint32 `json:"index"`
	Path    string `json:"path"`
	Address string `json:"address"`
}

type signRequest struct {
	Index    uint32 `json:"index"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
}

type signResponse struct {
	Index     uint32 `json:"index"`
	Path      string `json:"path"`
	Address   string `json:"address"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// --- 辅助函数 ---

// decodeJSON 读取并解析请求体，拒绝未知字段和多余内容。
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("请求体不是合法 JSON: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("请求体只能包含一个 JSON 对象")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("写出响应失败", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

// parseUint32 解析路径或 JSON 里的无符号 32 位整数。
func parseUint32(raw string) (uint32, error) {
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q 不是合法的账户索引", raw)
	}
	return uint32(value), nil
}

// --- 中间件 ---

// statusRecorder 记录响应状态码，供日志使用。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		slog.Info("请求",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

// recoverPanic 兜住处理器里的 panic，避免单个请求把整个服务带崩。
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("处理器 panic", "path", r.URL.Path, "panic", recovered)
				writeError(w, http.StatusInternalServerError, "服务内部错误")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
