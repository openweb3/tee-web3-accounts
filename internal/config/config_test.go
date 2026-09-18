package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openweb3/tee-web3-accounts/internal/wallet"
)

const testMnemonic = "test test test test test test test test test test test junk"

// clearEnv 清掉所有相关环境变量，避免开发机上的残留影响测试。
func clearEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvMnemonic, EnvMnemonicFile, EnvPassphrase,
		EnvAccountRootPath, EnvListenAddr, EnvDataFile, EnvMaxUnlocks,
	} {
		t.Setenv(name, "")
	}
}

func TestFromEnvRequiresMnemonic(t *testing.T) {
	clearEnv(t)

	if _, err := FromEnv(); err == nil {
		t.Fatal("缺少助记词时应当直接报错，而不是使用任何默认值")
	}
}

func TestFromEnvRejectsAmbiguousMnemonic(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvMnemonic, testMnemonic)
	t.Setenv(EnvMnemonicFile, filepath.Join(t.TempDir(), "mnemonic.txt"))

	if _, err := FromEnv(); err == nil {
		t.Fatal("同时设置两个助记词来源时应当报错")
	}
}

func TestFromEnvReadsMnemonicFile(t *testing.T) {
	clearEnv(t)

	path := filepath.Join(t.TempDir(), "mnemonic.txt")
	// 故意加上首尾空白和换行，模拟 heredoc 写文件。
	if err := os.WriteFile(path, []byte("\n  "+testMnemonic+"  \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(EnvMnemonicFile, path)

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Mnemonic != testMnemonic {
		t.Errorf("助记词 = %q", cfg.Mnemonic)
	}
	if _, err := wallet.Open(cfg.WalletConfig()); err != nil {
		t.Errorf("读到的助记词无法构造钱包: %v", err)
	}
}

func TestFromEnvRejectsEmptyMnemonicFile(t *testing.T) {
	clearEnv(t)

	path := filepath.Join(t.TempDir(), "mnemonic.txt")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv(EnvMnemonicFile, path)

	if _, err := FromEnv(); err == nil {
		t.Fatal("空文件应当报错")
	}
}

func TestFromEnvDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvMnemonic, testMnemonic)

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.DataFile != DefaultDataFile {
		t.Errorf("DataFile = %q, want %q", cfg.DataFile, DefaultDataFile)
	}
	if cfg.AccountRootPath != wallet.DefaultAccountRootPath {
		t.Errorf("AccountRootPath = %q", cfg.AccountRootPath)
	}
	if cfg.MaxConcurrentUnlocks != 0 {
		t.Errorf("MaxConcurrentUnlocks = %d, want 0（表示用 API 层默认值）", cfg.MaxConcurrentUnlocks)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvMnemonic, testMnemonic)
	t.Setenv(EnvPassphrase, "extra")
	t.Setenv(EnvAccountRootPath, "m/44'/60'/0'/0")
	t.Setenv(EnvListenAddr, "0.0.0.0:9999")
	t.Setenv(EnvDataFile, "/tmp/accounts.json")
	t.Setenv(EnvMaxUnlocks, "8")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.MnemonicPassphrase != "extra" {
		t.Errorf("MnemonicPassphrase = %q", cfg.MnemonicPassphrase)
	}
	if cfg.ListenAddr != "0.0.0.0:9999" || cfg.DataFile != "/tmp/accounts.json" {
		t.Errorf("覆盖没生效: %+v", cfg)
	}
	if cfg.MaxConcurrentUnlocks != 8 {
		t.Errorf("MaxConcurrentUnlocks = %d", cfg.MaxConcurrentUnlocks)
	}

	// 带额外口令的钱包应当派生出与不带口令时不同的地址。
	withPassphrase, err := wallet.Open(cfg.WalletConfig())
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	withoutPassphrase, err := wallet.Open(wallet.Config{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("wallet.Open: %v", err)
	}
	first, err := withPassphrase.Address(0)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	second, err := withoutPassphrase.Address(0)
	if err != nil {
		t.Fatalf("Address: %v", err)
	}
	if first == second {
		t.Error("BIP-39 额外口令没有影响派生结果")
	}
}

func TestFromEnvRejectsBadMaxUnlocks(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvMnemonic, testMnemonic)

	for _, value := range []string{"0", "-1", "abc", "1.5"} {
		t.Setenv(EnvMaxUnlocks, value)
		if _, err := FromEnv(); err == nil {
			t.Errorf("%q 应当被拒绝", value)
		}
	}
}

func TestValidateRejectsBlankFields(t *testing.T) {
	tests := []Config{
		{ListenAddr: ":8080", DataFile: "x", Mnemonic: "   "},
		{Mnemonic: testMnemonic, DataFile: "x"},
		{Mnemonic: testMnemonic, ListenAddr: ":8080"},
		{Mnemonic: testMnemonic, ListenAddr: ":8080", DataFile: "x", MaxConcurrentUnlocks: -1},
	}
	for _, cfg := range tests {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%+v 应当被拒绝", cfg)
		} else if !strings.Contains(err.Error(), "config") {
			t.Errorf("错误信息缺少前缀: %v", err)
		}
	}
}
