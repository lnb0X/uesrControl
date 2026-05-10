# userControl

基于 Go 的用户权限管控与额度管理平台。

## 功能特性

- **用户认证体系** — 注册/登录（QQ号 + 邮箱验证码）、密码修改、找回密码
- **Session 管理** — Redis 分布式会话，默认7天，支持"记住登录"30天持久化
- **安全防护** — 登录失败锁定（3次错误锁10分钟）、AES对称加密、Session Token随机生成
- **额度管理** — 用户每日免费额度自动重置、CDK兑换码提升上限、管理员手动调整
- **管理后台** — 全局数据统计、用户启停用、额度调整、Token刷新、CDK批量生成
- **内部服务通道** — `/internal/*` 接口供下游业务服务（如AI Bot网关）进行服务间鉴权与额度扣减
- **定时任务** — 每日凌晨自动重置所有用户免费额度

## 技术栈

| 组件 | 技术 |
|---|---|
| 语言 | Go 1.25 |
| Web框架 | Gin |
| 数据库 | PostgreSQL (pgx) |
| 缓存/会话 | Redis (go-redis) |
| 加密 | AES (golang.org/x/crypto) |
| 前端 | Vue 3 + WeUI + Axios |

## 项目结构

```
userControl/
├── main.go                 # 入口：初始化DB/Redis/HTTP/定时任务
├── router.go               # 路由注册（公开/用户/管理员/内部四层）
├── middleware.go           # 鉴权中间件（Admin Session / Internal Secret）
├── tasks.go                # 定时任务（每日额度重置）
├── handlers_user.go        # 用户接口 Handler
├── handlers_admin.go       # 管理员接口 Handler
├── handlers_internal.go    # 内部服务接口 Handler
├── admin.html              # 管理后台前端页面
├── user_dashboard.html     # 用户面板前端页面
├── config/
│   └── config.go           # 配置结构体定义 & 加载逻辑
├── func/
│   ├── pgsqlOperate/       # PostgreSQL DAO 层（用户CRUD、资产、CDK）
│   ├── redis/              # Redis 操作（Session管理、CDK去重）
│   ├── mail/               # 邮件发送（验证码）
│   └── utils/              # 工具函数（AES加密、Token生成等）
├── config.example.json     # 配置模板（复制为 config.json 使用）
├── go.mod / go.sum         # Go 依赖
└── README.md               # 本文件
```

## 快速开始

### 环境要求

- Go >= 1.21
- PostgreSQL >= 14
- Redis >= 6
- SMTP 邮箱服务（用于发送验证码）

### 1. 克隆项目

```bash
git clone https://github.com/lnb0X/uesrControl
cd userControl
```

### 2. 配置

```bash
cp config.example.json config.json
# 编辑 config.json，填写真实的数据库密码、Redis密码、邮箱SMTP等
```

配置项说明：

| 字段 | 说明 |
|---|---|
| `server.port` | 监听端口，默认 `8080` |
| `server.mode` | 运行模式：`debug` / `release` |
| `enable_register` | 是否开放注册 |
| `postgres.*` | PostgreSQL 连接参数 |
| `redis.*` | Redis 连接参数 |
| `admin.*` | 管理员账号密码 |
| `email.*` | SMTP 邮件配置（验证码发送） |
| `internal_secret` | 内部服务调用共享密钥 |
| `aes_secret_key` | CDK 加解密密钥（32位十六进制字符串） |

> 也支持**环境变量覆盖**配置文件（详见 `config/config.go`），方便 Docker 部署。

### 3. 初始化数据库

在 PostgreSQL 中创建数据库和表结构：

```sql
CREATE DATABASE usercontrol;
\c usercontrol

-- 建表SQL请参考 func/pgsqlOperate/user_dao.go 中的建表语句
-- 或首次运行时程序会自动检测并提示缺失的表
```

### 4. 安装依赖 & 运行

```bash
go mod download
go run main.go
```

或编译后运行：

```bash
go build -o userControl.exe .
./userControl.exe
```

### 5. 访问

| 页面 | 地址 |
|---|---|
| 用户面板 | http://localhost:8080/user |
| 管理后台 | http://localhost:8080/admin |

## API 概览

### 公开接口（无需登录）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/send_captcha` | 发送邮箱验证码 |
| POST | `/api/user/register` | 用户注册 |
| POST | `/api/user/login` | 用户登录 |
| POST | `/api/user/reset_password` | 重置密码 |
| POST | `/api/admin/login` | 管理员登录 |

### 用户接口（需 X-Session-Token）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/user/me` | 获取当前用户信息 |
| POST | `/api/user/change-password` | 修改密码 |
| POST | `/api/user/regen_token` | 重新生成访问Token |
| POST | `/api/user_use_cdk` | 使用CDK兑换码 |

### 管理员接口（需 Admin-Token）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/admin/dashboard/stats` | 全局统计 |
| POST | `/api/admin/user/set_status` | 设置用户启停用 |
| POST | `/api/admin/user/set_limit` | 设置用户额度上限 |
| POST | `/api/admin/user/reset_password` | 重置用户密码 |
| POST | `/api/admin/user/regen_token` | 刷新用户Token |
| POST | `/api/admin/generate_cdk` | 生成单个CDK |
| POST | `/api/admin/generate_cdk_batch` | 批量生成CDK |
| GET/POST | `/api/admin/config` | 查看/修改系统配置 |

### 内部服务接口（需 X-Server-Secret）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/internal/check_token` | 校验用户Token有效性 |
| POST | `/internal/deduct` | 扣减用户额度 |

## 安全说明

- 所有敏感配置（数据库密码、密钥等）存储在 `config.json` 中，该文件已加入 `.gitignore` **切勿提交**
- 密码经哈希处理后存储，不可逆
- Session Token 为随机生成的不可推测字符串
- API 传输层敏感数据采用 AES 加密
- 连续3次登录失败自动锁定账户10分钟

## 致谢

本项目在开发过程中使用了 [Vibe](https://www.codebuddy.ai/)（AI 辅助编程工具），用于代码生成、调试辅助与安全审查。

## License

MIT
