package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openweb3/tee-web3-accounts/internal/store"
	"github.com/openweb3/tee-web3-accounts/internal/wallet"
)

// 密码策略。密码是这套服务上唯一的身份凭据，同时也是解锁私钥的唯一钥匙，
// 所以设一个下限；上限则是为了给 Argon2id 的输入长度封顶。
const (
	MinPasswordLength = 8
	MaxPasswordLength = 1024
)

// handleHealth 供存活探针和部署脚本使用。
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleCreateAccount 创建账户：分配索引、实时派生地址、存下密码验证子。
// 私钥既不落盘也不返回，服务端自己也不留。
func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	// 创建会消耗 Argon2 时间并写盘，配置了 admin token 时必须有准入凭据，
	// 否则任何人都能用创建请求把服务拖住。
	if s.adminToken != "" && !tokenMatches(s.adminToken, r.Header.Get("Authorization")) {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}

	var request createAccountRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validatePassword(request.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	release, ok := tryAcquire(s.creates)
	if !ok {
		writeUnavailable(w)
		return
	}
	defer release()

	account, err := s.store.Create(request.Password, s.wallet.Address)
	if err != nil {
		if errors.Is(err, store.ErrCapacity) {
			writeError(w, http.StatusServiceUnavailable, "账户数量已达上限")
			return
		}
		slog.Error("创建账户失败", "error", err)
		writeError(w, http.StatusInternalServerError, "创建账户失败")
		return
	}

	writeJSON(w, http.StatusCreated, accountResponse{
		Index:   account.Index,
		Path:    s.wallet.AccountPath(account.Index),
		Address: account.Address,
	})
}

// tokenMatches 常数时间比较 Authorization 头里的 Bearer token。
// 先各自 SHA-256 再比较：定长摘要让 ConstantTimeCompare 覆盖全部内容，
// 不必（也不该）用长度预比较提前短路——那会泄露 token 长度。
func tokenMatches(want, header string) bool {
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return false
	}
	wantSum := sha256.Sum256([]byte(want))
	gotSum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(wantSum[:], gotSum[:]) == 1
}

// handleGetAccount 按索引查询地址。地址是公开信息，不需要密码。
func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	index, err := parseUint32(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	account, err := s.resolve(index)
	if err != nil {
		writeAccountError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, accountResponse{
		Index:   index,
		Path:    s.wallet.AccountPath(index),
		Address: account.Address,
	})
}

// errAccountNotFound 表示索引在账户库里不存在。
var errAccountNotFound = errors.New("api: 账户不存在")

// resolve 取出索引对应的账户记录，并确认它与当前助记词一致。
//
// 签名与查询两条路径都必须过这一关，理由见 wallet.CheckAddress。
func (s *Server) resolve(index uint32) (store.Account, error) {
	account, ok := s.store.Get(index)
	if !ok {
		return store.Account{}, errAccountNotFound
	}
	if err := s.wallet.CheckAddress(index, account.Address); err != nil {
		if errors.Is(err, wallet.ErrAddressMismatch) {
			slog.Error("地址与账户库不一致，助记词可能被换过",
				"index", index, "error", err)
		} else {
			slog.Error("派生地址失败", "index", index, "error", err)
		}
		return store.Account{}, err
	}
	return account, nil
}

// writeAccountError 把 resolve 的错误映射成响应。索引不存在是 404，其余是服务端故障。
func writeAccountError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAccountNotFound):
		writeError(w, http.StatusNotFound, "账户不存在")
	case errors.Is(err, wallet.ErrAddressMismatch):
		writeError(w, http.StatusInternalServerError, "服务端助记词与账户库不一致")
	default:
		writeError(w, http.StatusInternalServerError, "派生地址失败")
	}
}

// handleSign 用指定账户对 32 字节哈希签名。
//
// 密码在这里只做身份校验；私钥不带密码因素，由助记词 + 索引现场派生，签完立刻抹掉。
func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	var request signRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := parseHash(request.Hash)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	release, ok := tryAcquire(s.unlocks)
	if !ok {
		writeUnavailable(w)
		return
	}
	defer release()

	// 顺序要紧：先校验密码，再解析账户。解析会把「索引不存在」变成 404，
	// 放在校验之前就等于对外宣布这个索引存不存在 —— 而密码是这里唯一的
	// 门禁，索引可枚举，所以不存在与密码错误必须返回完全相同的结果。
	if err := s.store.VerifyPassword(request.Index, request.Password); err != nil {
		var lockErr *store.LockoutError
		switch {
		case errors.As(err, &lockErr):
			// 响应体与普通失败完全一致，只加 Retry-After 提示重试时机。
			seconds := int((lockErr.RetryAfter + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
			writeError(w, http.StatusUnauthorized, "索引或密码不正确")
		case errors.Is(err, store.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "索引或密码不正确")
		default:
			slog.Error("校验密码失败", "index", request.Index, "error", err)
			writeError(w, http.StatusInternalServerError, "校验密码失败")
		}
		return
	}

	// 密码已通过，此时解析必然成功。校验与签名针对的是同一条记录，中途不会被
	// 换掉；地址一致性也在这里顺带确认。
	account, err := s.resolve(request.Index)
	if err != nil {
		writeAccountError(w, err)
		return
	}

	signing, err := s.wallet.Account(request.Index)
	if err != nil {
		slog.Error("派生账户失败", "index", request.Index, "error", err)
		writeError(w, http.StatusInternalServerError, "派生账户失败")
		return
	}
	defer signing.Destroy()

	signature, err := signing.Sign(hash)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, signResponse{
		Index:     request.Index,
		Path:      s.wallet.AccountPath(request.Index),
		Address:   account.Address,
		Hash:      "0x" + hex.EncodeToString(hash),
		Signature: "0x" + hex.EncodeToString(signature),
	})
}

// writeUnavailable 在密码校验通道打满时回背压，让客户端稍后重试。
func writeUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeError(w, http.StatusServiceUnavailable, "服务繁忙，请稍后重试")
}

// validatePassword 只用于创建账户时执行密码策略；校验已有密码时不走这里。
func validatePassword(password string) error {
	switch {
	case password == "":
		return errors.New("密码不能为空")
	case utf8.RuneCountInString(password) < MinPasswordLength:
		return fmt.Errorf("密码至少 %d 个字符", MinPasswordLength)
	case len(password) > MaxPasswordLength:
		return fmt.Errorf("密码最多 %d 字节", MaxPasswordLength)
	}
	return nil
}

// parseHash 解析待签名的哈希，接受带或不带 0x 前缀的 64 位十六进制字符串。
func parseHash(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) >= 2 && (trimmed[:2] == "0x" || trimmed[:2] == "0X") {
		trimmed = trimmed[2:]
	}
	hash, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, errors.New("hash 必须是十六进制字符串")
	}
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash 必须是 32 字节（64 个十六进制字符），实际 %d 字节", len(hash))
	}
	return hash, nil
}
