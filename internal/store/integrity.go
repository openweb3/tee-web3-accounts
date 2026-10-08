package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// 账户库完整性保护。
//
// 威胁模型：宿主机不可信。它能读写 guest 的磁盘，但拿不到助记词（助记词只在
// TEE 内存里）。如果账户库是明文可改的，宿主机把某个账户的 PasswordHash 换成
// 自己知道的密码的 Argon2 输出，就能用自选密码通过校验、进而用该账户签名 —
// 而启动护栏只比对地址，对这种篡改完全无感（地址可以原样保留）。
//
// 解法是用助记词派生的密钥给整库算 HMAC-SHA256。宿主机没有助记词，就算改了
// 内容也算不出合法 MAC。密钥走独立域标签（见 wallet.integrityKeyLabel），所以
// 即使攻击者已经从别处拿到 BIP-32 账户根私钥，也不足以伪造 MAC。

// mac 计算整库的 HMAC，返回 base64 编码。
//
// 覆盖范围是「除 Mac 字段以外的全部字段」，用规范化 JSON（字段顺序由结构体
// 定义固定）作为输入，因此与 map 式的序列化无关，同样的内容永远得到同样的 MAC。
func (d fileData) mac(key []byte) (string, error) {
	if len(key) == 0 {
		return "", errors.New("store: 缺少完整性密钥")
	}
	// 副本置空 Mac 字段后再序列化，避免自引用。
	clone := d
	clone.Mac = ""
	// Accounts 已保证是 nil 或非空切片，两者序列化结果不同即长度可区分，
	// 无需为「nil 与空数组等价」额外做规范化。
	payload, err := json.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("store: 序列化账户库以计算 MAC 失败: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyMac 校验完整性。空库（一条记录都没有）不做校验：首次启动时文件由本进程
// 自己写出，不存在被篡改的窗口。
func (d fileData) verifyMac(key []byte) error {
	if len(d.Accounts) == 0 {
		return nil
	}
	if d.Mac == "" {
		return errors.New("账户库缺少完整性校验（mac 字段为空），拒绝加载")
	}
	expected, err := d.mac(key)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(expected), []byte(d.Mac)) {
		return errors.New(
			"账户库完整性校验失败，内容与启动时的密钥不匹配。" +
				"这通常意味着文件在 TEE 之外被改写过（最典型的是密码验证子被替换）。" +
				"请恢复该文件的原始副本，不要在受影响的账户库上继续服务")
	}
	return nil
}
