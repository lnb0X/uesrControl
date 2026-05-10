package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ConfigFile 默认配置文件路径
const ConfigFile = "config.json"

// AppConfig 顶层配置结构
type AppConfig struct {
	Server         ServerConfig    `json:"server"`
	EnableRegister bool            `json:"enable_register"`
	Postgres       PostgresConfig  `json:"postgres"`
	Redis          RedisConfig     `json:"redis"`
	Admin          AdminConfig     `json:"admin"`
	Email          EmailConfig     `json:"email"`
	InternalSecret string          `json:"internal_secret"`
	AESSecretKey   string          `json:"aes_secret_key"` // CDK 加解密密钥
}

// ServerConfig 服务配置
type ServerConfig struct {
	Port string `json:"port"`
	Mode string `json:"mode"`
}

// PostgresConfig PostgreSQL 配置
type PostgresConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	DBName   string `json:"database"`
	SSLMode  string `json:"sslmode"`
}

// RedisConfig Redis 配置
type RedisConfig struct {
	Addr     string `json:"addr"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// AdminConfig 管理员配置
type AdminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// EmailConfig 邮件配置
type EmailConfig struct {
	From     string `json:"from"`
	Password string `json:"password"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// --- 兼容旧代码的类型别名 ---

type ServerEnv = ServerConfig
type PostgresEnv = PostgresConfig
type RedisEnv  = RedisConfig

// PgDB 保持兼容（DAO 层引用）
type PgDB struct {
	Pool *pgxpool.Pool
}

// 全局配置实例与读写锁
var (
	globalConfig *AppConfig
	configMu     sync.RWMutex
)

// Load 从 config.json 加载配置，环境变量可覆盖同名项
func Load() *AppConfig {
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		log.Fatalf("[Config] 无法读取配置文件 %s: %v", ConfigFile, err)
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("[Config] 配置文件 JSON 解析失败: %v", err)
	}

	// 环境变量覆盖（方便容器部署）
	if v := os.Getenv("PGUSER"); v != "" { cfg.Postgres.User = v }
	if v := os.Getenv("PGPASSWORD"); v != "" { cfg.Postgres.Password = v }
	if v := os.Getenv("PGHOST"); v != "" { cfg.Postgres.Host = v }
	if v := os.Getenv("PGPORT"); v != "" { cfg.Postgres.Port = v }
	if v := os.Getenv("PGDATABASE"); v != "" { cfg.Postgres.DBName = v }
	if v := os.Getenv("PGSSLMODE"); v != "" { cfg.Postgres.SSLMode = v }

	if v := os.Getenv("ServerPort"); v != "" { cfg.Server.Port = v }
	if v := os.Getenv("ServerMode"); v != "" { cfg.Server.Mode = v }

	if v := os.Getenv("RedisAddr"); v != "" { cfg.Redis.Addr = v }
	if v := os.Getenv("RedisPassword"); v != "" { cfg.Redis.Password = v }
	if v := os.Getenv("RedisDB"); v != "" { if d, e := strconv.Atoi(v); e == nil { cfg.Redis.DB = d } }

	if v := os.Getenv("ADMIN_USER"); v != "" { cfg.Admin.Username = v }
	if v := os.Getenv("ADMIN_PASS"); v != "" { cfg.Admin.Password = v }

	if v := os.Getenv("EmailFrom"); v != "" { cfg.Email.From = v }
	if v := os.Getenv("EmailPassword"); v != "" { cfg.Email.Password = v }
	if v := os.Getenv("EmailHost"); v != "" { cfg.Email.Host = v }
	if v := os.Getenv("EmailPort"); v != "" { if p, e := strconv.Atoi(v); e == nil { cfg.Email.Port = p } }

	if v := os.Getenv("InternalSecret"); v != "" { cfg.InternalSecret = v }
	if v := os.Getenv("AES_SECRET_KEY"); v != "" { cfg.AESSecretKey = v }

	// 设置默认值
	if cfg.Server.Port == "" { cfg.Server.Port = "8080" }
	if cfg.Server.Mode == "" { cfg.Server.Mode = "release" }
	if cfg.Postgres.SSLMode == "" { cfg.Postgres.SSLMode = "disable" }
	if cfg.Email.Port == 0 { cfg.Email.Port = 465 }

	// 必填校验
	if cfg.Postgres.User == "" || cfg.Postgres.Password == "" || cfg.Postgres.Host == "" || cfg.Postgres.DBName == "" {
		log.Fatal("[Config] 缺少 PostgreSQL 核心连接参数 (user/password/host/database)")
	}
	if cfg.Redis.Addr == "" {
		log.Fatal("[Config] 缺少 Redis 连接参数")
	}
	if cfg.Admin.Username == "" || cfg.Admin.Password == "" {
		log.Fatal("[Config] 缺少管理员账号或密码")
	}
	if cfg.InternalSecret == "" {
		log.Fatal("[Config] 缺少 InternalSecret")
	}
	if cfg.AESSecretKey == "" {
		log.Fatal("[Config] 缺少 aes_secret_key（CDK 加解密密钥）")
	}
	if kLen := len(cfg.AESSecretKey); kLen != 16 && kLen != 24 && kLen != 32 {
		log.Fatalf("[Config] aes_secret_key 长度无效：当前 %d 字节，仅支持 16(AES-128)/24(AES-192)/32(AES-256) 字节", kLen)
	}

	configMu.Lock()
	globalConfig = &cfg
	configMu.Unlock()

	return &cfg
}

// Get 返回当前全局配置（只读副本）
func Get() AppConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	if globalConfig == nil {
		log.Fatal("[Config] 配置尚未初始化，请先调用 Load()")
	}
	return *globalConfig
}

// GetAESSecretKey 返回 CDK 加解密密钥
func GetAESSecretKey() string {
	configMu.RLock()
	defer configMu.RUnlock()
	if globalConfig == nil {
		log.Fatal("[Config] 配置尚未初始化，请先调用 Load()")
	}
	return globalConfig.AESSecretKey
}

// Save 将配置写回 config.json
func Save(cfg *AppConfig) error {
	configMu.Lock()
	defer configMu.Unlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	if err := os.WriteFile(ConfigFile, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	globalConfig = cfg
	return nil
}

// UpdatePartial 安全地部分更新全局配置并持久化
func UpdatePartial(updates map[string]interface{}) error {
	configMu.Lock()
	defer configMu.Unlock()

	cfgCopy := *globalConfig // 浅拷贝

	// server
	if s, ok := updates["server"].(map[string]interface{}); ok {
		if v, ok := s["port"].(string); ok { cfgCopy.Server.Port = v }
		if v, ok := s["mode"].(string); ok { cfgCopy.Server.Mode = v }
	}
	// postgres
	if p, ok := updates["postgres"].(map[string]interface{}); ok {
		if v, ok := p["user"].(string); ok { cfgCopy.Postgres.User = v }
		if v, ok := p["password"].(string); ok && v != "******" { cfgCopy.Postgres.Password = v }
		if v, ok := p["host"].(string); ok { cfgCopy.Postgres.Host = v }
		if v, ok := p["port"].(string); ok { cfgCopy.Postgres.Port = v }
		if v, ok := p["database"].(string); ok { cfgCopy.Postgres.DBName = v }
		if v, ok := p["sslmode"].(string); ok { cfgCopy.Postgres.SSLMode = v }
	}
	// admin
	if a, ok := updates["admin"].(map[string]interface{}); ok {
		if v, ok := a["username"].(string); ok { cfgCopy.Admin.Username = v }
		if v, ok := a["password"].(string); ok && v != "******" { cfgCopy.Admin.Password = v }
	}
	// email
	if e, ok := updates["email"].(map[string]interface{}); ok {
		if v, ok := e["from"].(string); ok { cfgCopy.Email.From = v }
		if v, ok := e["password"].(string); ok && v != "******" { cfgCopy.Email.Password = v }
		if v, ok := e["host"].(string); ok { cfgCopy.Email.Host = v }
		if v, ok := e["port"]; ok {
			switch val := v.(type) {
			case float64: cfgCopy.Email.Port = int(val)
			case int:    cfgCopy.Email.Port = val
			}
		}
	}
	// redis
	if r, ok := updates["redis"].(map[string]interface{}); ok {
		if v, ok := r["addr"].(string); ok { cfgCopy.Redis.Addr = v }
		if v, ok := r["password"].(string); ok && v != "******" { cfgCopy.Redis.Password = v }
		if v, ok := r["db"]; ok {
			switch val := v.(type) {
			case float64: cfgCopy.Redis.DB = int(val)
			case int:    cfgCopy.Redis.DB = val
			}
		}
	}
	// internal_secret
	if v, ok := updates["internal_secret"].(string); ok && v != "******" { cfgCopy.InternalSecret = v }
	// aes_secret_key
	if v, ok := updates["aes_secret_key"].(string); ok && v != "******" { cfgCopy.AESSecretKey = v }
	// enable_register
	if v, ok := updates["enable_register"]; ok {
		switch val := v.(type) {
		case bool:   cfgCopy.EnableRegister = val
		case string: cfgCopy.EnableRegister = (val != "false" && val != "0" && val != "")
		}
	}

	data, err := json.MarshalIndent(cfgCopy, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}
	if err := os.WriteFile(ConfigFile, data, 0644); err != nil {
		return fmt.Errorf("写入失败: %w", err)
	}
	globalConfig = &cfgCopy
	return nil
}

// --- 兼容旧接口 ---

func LoadEvn() (PostgresEnv, ServerEnv, RedisEnv, AdminConfig, EmailConfig, string) {
	cfg := Load()
	return cfg.Postgres, cfg.Server, cfg.Redis, cfg.Admin, cfg.Email, cfg.InternalSecret
}

func LoadServerEnv() ServerEnv {
	cfg := Get()
	return cfg.Server
}

// --- 请求模型（保持不变）---

type UserRegisterRequest struct {
	QQ       string `json:"qq" binding:"required"`
	Password string `json:"password" binding:"required"`
	Captcha  string `json:"captcha" binding:"required"`
}

type SengCaptchaRequest struct {
	QQ     string `json:"qq" binding:"required"`
	Action string `json:"action" binding:"required"`
}
