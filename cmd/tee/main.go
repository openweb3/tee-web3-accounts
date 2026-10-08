// Command tee 是运行在可信执行环境里的 Web3 账户托管服务。
//
// 它只做三件事：按密码创建账户、按索引查询地址、按密码对哈希签名。私钥由启动时
// 配置的助记词在现场派生，既不落盘也不缓存，进程退出即消失；持久化的只有
// 「索引 -> 密码验证子」以及给助记词做一致性护栏的地址。
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/openweb3/tee-web3-accounts/internal/api"
	"github.com/openweb3/tee-web3-accounts/internal/config"
	"github.com/openweb3/tee-web3-accounts/internal/store"
	"github.com/openweb3/tee-web3-accounts/internal/wallet"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if err := run(); err != nil {
		slog.Error("服务启动失败", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	// 助记词在这里被完整校验（词表 + 校验和）；配错就拒绝启动，而不是起一个
	// 会派生错地址的服务。
	accountWallet, err := wallet.Open(cfg.WalletConfig())
	if err != nil {
		return err
	}
	warnIfTestMnemonic(cfg.Mnemonic)

	if dir := filepath.Dir(cfg.DataFile); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("创建账户库目录 %s 失败: %w", dir, err)
		}
	}

	accountStore, err := store.Open(cfg.DataFile, cfg.Argon2Params, accountWallet.IntegrityKey())
	if err != nil {
		return err
	}
	accountStore.SetMaxAccounts(cfg.MaxAccounts)

	// 启动时确认账户库里的地址都能由当前助记词重新派生出来。换错助记词是这套
	// 系统最危险的静默故障，必须在这里拦住。
	if err := accountStore.VerifyAddresses(accountWallet.Address); err != nil {
		return err
	}

	server, err := api.New(api.Config{
		Wallet:               accountWallet,
		Store:                accountStore,
		AdminToken:           cfg.AdminToken,
		MaxConcurrentUnlocks: cfg.MaxConcurrentUnlocks,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second, // 密码校验要跑 Argon2id，留足余量
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	slog.Info("TEE 账户托管服务启动",
		"listen", cfg.ListenAddr,
		"data_file", cfg.DataFile,
		"account_root_path", accountWallet.AccountRootPath(),
		"argon2", fmt.Sprintf("t=%d m=%d KiB p=%d",
			cfg.Argon2Params.Time, cfg.Argon2Params.MemoryKiB, cfg.Argon2Params.Threads),
		"accounts", accountStore.Len(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("监听 %s 失败: %w", cfg.ListenAddr, err)
	case <-ctx.Done():
	}

	slog.Info("收到退出信号，开始优雅关闭")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("优雅关闭失败: %w", err)
	}
	return nil
}

// knownTestMnemonics 是各工具链默认的公开测试助记词。生产 TEE 用了它们等于把
// 私钥公开；这里只告警不拒绝，因为本仓库自己的 e2e 与 cloudtest 就在用它们。
var knownTestMnemonics = []string{
	"test test test test test test test test test test test junk",
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
}

func warnIfTestMnemonic(mnemonic string) {
	for _, known := range knownTestMnemonics {
		if mnemonic == known {
			slog.Warn("检测到公开的测试助记词，不要用它托管真实资产",
				"hint", "生产环境请通过 TEE_MNEMONIC_FILE 配置一个全新生成的助记词")
			return
		}
	}
}
