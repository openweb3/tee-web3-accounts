// Package config 从环境变量读取 TEE 服务的启动配置。
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/openweb3/tee-web3-accounts/internal/store"
	"github.com/openweb3/tee-web3-accounts/internal/wallet"
)

// 配置项名。用环境变量而不是配置文件，是为了让部署脚本（含 cloudtest）能直接注入，
// 且助记词可以只经过一次内存传递。
const (
	EnvMnemonic          = "TEE_MNEMONIC"
	EnvMnemonicFile      = "TEE_MNEMONIC_FILE"
	EnvPassphrase        = "TEE_MNEMONIC_PASSPHRASE"
	EnvAccountRootPath   = "TEE_ACCOUNT_ROOT_PATH"
	EnvListenAddr        = "TEE_LISTEN_ADDR"
	EnvDataFile          = "TEE_DATA_FILE"
	EnvMaxUnlocks        = "TEE_MAX_CONCURRENT_UNLOCKS"
	EnvAdminToken        = "TEE_ADMIN_TOKEN"
	EnvMaxAccounts       = "TEE_MAX_ACCOUNTS"
	EnvAllowPublicListen = "TEE_ALLOW_PUBLIC_LISTEN"
	EnvArgon2Time        = "TEE_ARGON2_TIME"
	EnvArgon2MemoryKiB   = "TEE_ARGON2_MEMORY_KIB"
	EnvArgon2Threads     = "TEE_ARGON2_THREADS"
)

// 默认值。监听地址默认只绑回环：TEE 上不该把托管接口直接暴露到公网。
const (
	DefaultListenAddr = "127.0.0.1:8080"
	DefaultDataFile   = "data/accounts.json"
)

// Config 是服务启动所需的全部配置。
type Config struct {
	Mnemonic             string
	MnemonicPassphrase   string
	AccountRootPath      string
	ListenAddr           string
	DataFile             string
	MaxConcurrentUnlocks int
	AdminToken           string
	MaxAccounts          uint32
	AllowPublicListen    bool
	Argon2Params         store.Argon2Params
}

// argon2Defaults 是各项代价参数的缺省值。三项分开配置而不是打包成一个
// 「强度档位」，是因为调高内存和调高迭代轮数对机器的压测方式完全不同。
var argon2Defaults = store.Argon2Params{
	Time:      store.DefaultArgon2Params.Time,
	MemoryKiB: store.DefaultArgon2Params.MemoryKiB,
	Threads:   store.DefaultArgon2Params.Threads,
	KeyLength: store.DefaultArgon2Params.KeyLength,
}

// readArgon2Params 读三项 Argon2 代价参数。留空即用默认值，非法值直接报错 ——
// 代价参数写错会直接决定密码验证的抗爆破能力，不该被静默兜底。
func readArgon2Params() (store.Argon2Params, error) {
	params := argon2Defaults

	if err := readUint32Env(EnvArgon2Time, &params.Time); err != nil {
		return store.Argon2Params{}, err
	}
	if err := readUint32Env(EnvArgon2MemoryKiB, &params.MemoryKiB); err != nil {
		return store.Argon2Params{}, err
	}
	rawThreads := uint32(params.Threads)
	if err := readUint32Env(EnvArgon2Threads, &rawThreads); err != nil {
		return store.Argon2Params{}, err
	}
	if rawThreads > 255 {
		return store.Argon2Params{}, fmt.Errorf("%s=%d 超出 [1,255]", EnvArgon2Threads, rawThreads)
	}
	params.Threads = uint8(rawThreads)

	if err := params.Validate(); err != nil {
		return store.Argon2Params{}, err
	}
	return params, nil
}

// readUint32Env 把一个环境变量读进 dst，留空则不动 dst。
func readUint32Env(name string, dst *uint32) error {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return fmt.Errorf("%s 必须是正整数，实际 %q", name, raw)
	}
	*dst = uint32(value)
	return nil
}

// FromEnv 读取配置。缺失或冲突的配置一律直接报错，不做任何兜底默认 —— 尤其是助记词，
// 给默认值等于把所有人的资产都交给一个公开的种子。
func FromEnv() (Config, error) {
	mnemonic, err := readMnemonic()
	if err != nil {
		return Config{}, err
	}

	argon2Params, err := readArgon2Params()
	if err != nil {
		return Config{}, err
	}

	maxUnlocks := 0
	if raw := strings.TrimSpace(os.Getenv(EnvMaxUnlocks)); raw != "" {
		maxUnlocks, err = strconv.Atoi(raw)
		if err != nil || maxUnlocks < 1 {
			return Config{}, fmt.Errorf("%s 必须是正整数，实际 %q", EnvMaxUnlocks, raw)
		}
	}

	maxAccounts := uint32(0)
	if raw := strings.TrimSpace(os.Getenv(EnvMaxAccounts)); raw != "" {
		value, parseErr := strconv.ParseUint(raw, 10, 32)
		if parseErr != nil || value < 1 {
			return Config{}, fmt.Errorf("%s 必须是正整数，实际 %q", EnvMaxAccounts, raw)
		}
		maxAccounts = uint32(value)
	}

	cfg := Config{
		Mnemonic:             mnemonic,
		MnemonicPassphrase:   os.Getenv(EnvPassphrase),
		AccountRootPath:      strings.TrimSpace(os.Getenv(EnvAccountRootPath)),
		ListenAddr:           strings.TrimSpace(os.Getenv(EnvListenAddr)),
		DataFile:             strings.TrimSpace(os.Getenv(EnvDataFile)),
		MaxConcurrentUnlocks: maxUnlocks,
		AdminToken:           os.Getenv(EnvAdminToken),
		MaxAccounts:          maxAccounts,
		AllowPublicListen:    strings.TrimSpace(os.Getenv(EnvAllowPublicListen)) == "1",
		Argon2Params:         argon2Params,
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if cfg.DataFile == "" {
		cfg.DataFile = DefaultDataFile
	}
	if cfg.AccountRootPath == "" {
		cfg.AccountRootPath = wallet.DefaultAccountRootPath
	}
	// 本服务没有客户端认证，绑到非回环等于把密码爆破面直接打开；必须显式放行。
	if !cfg.AllowPublicListen && !isLoopback(cfg.ListenAddr) {
		return Config{}, fmt.Errorf("%s=%q 不是回环地址；本服务没有客户端认证，"+
			"必须显式设置 %s=1 才允许绑定非回环接口",
			EnvListenAddr, cfg.ListenAddr, EnvAllowPublicListen)
	}
	// 解析与完整性校验收敛到这一个入口，调用方无需再单独调 Validate。
	return cfg, cfg.Validate()
}

// isLoopback 判断监听地址是否绑定回环接口。注意 ":8080" 这种省略 host 的写法
// 会监听所有接口，不算回环。
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readMnemonic 从 TEE_MNEMONIC 或 TEE_MNEMONIC_FILE 读取助记词。
//
// 文件形式适合把助记词放在权限收紧的文件里，避免出现在进程环境变量中。
func readMnemonic() (string, error) {
	inline := strings.TrimSpace(os.Getenv(EnvMnemonic))
	file := strings.TrimSpace(os.Getenv(EnvMnemonicFile))

	switch {
	case inline != "" && file != "":
		return "", fmt.Errorf("%s 与 %s 只能设置一个", EnvMnemonic, EnvMnemonicFile)
	case inline != "":
		return inline, nil
	case file != "":
		raw, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("读取 %s 指定的助记词文件失败: %w", EnvMnemonicFile, err)
		}
		mnemonic := strings.TrimSpace(string(raw))
		if mnemonic == "" {
			return "", fmt.Errorf("%s 指定的文件 %s 是空的", EnvMnemonicFile, file)
		}
		return mnemonic, nil
	default:
		return "", fmt.Errorf("必须通过 %s 或 %s 配置助记词", EnvMnemonic, EnvMnemonicFile)
	}
}

// WalletConfig 转成钱包的构造参数。
func (c Config) WalletConfig() wallet.Config {
	return wallet.Config{
		Mnemonic:        c.Mnemonic,
		Passphrase:      c.MnemonicPassphrase,
		AccountRootPath: c.AccountRootPath,
	}
}

// Validate 做一次自检，确保配置项本身自洽。
// 并发上限为 0 表示「用 API 层的默认值」，不算错误。
func (c Config) Validate() error {
	if strings.TrimSpace(c.Mnemonic) == "" {
		return errors.New("config: 助记词不能为空")
	}
	if strings.TrimSpace(c.ListenAddr) == "" {
		return errors.New("config: 监听地址不能为空")
	}
	if strings.TrimSpace(c.DataFile) == "" {
		return errors.New("config: 账户库路径不能为空")
	}
	if c.MaxConcurrentUnlocks < 0 {
		return fmt.Errorf("config: 并发校验上限不能为负，实际 %d", c.MaxConcurrentUnlocks)
	}
	return nil
}
