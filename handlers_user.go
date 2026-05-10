package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"userControl/config"
	"userControl/func/mail"
	"userControl/func/pgsqlOperate"
	redisOperate "userControl/func/redis"
	"userControl/func/utils"
)

// ========== 依赖注入（由 router.go 在启动时设置） ==========
var (
	userDao    *pgsqlOperate.PgDB
	redisClient *redisOperate.Client
)

// InitHandlers 初始化 handler 层的共享依赖
// 由 main.go / router.go 在启动时调用一次
func InitHandlers(ud *pgsqlOperate.PgDB, rc *redisOperate.Client) {
	userDao = ud
	redisClient = rc
}

// ============================================================
//  用户公开接口 — 无需登录或需用户 Session
// ============================================================

// SendCaptchaHandler POST /api/send_captcha
// 发送邮箱验证码，支持 register 和 reset_password 两种 action
func SendCaptchaHandler(c *gin.Context) {
	var req config.SengCaptchaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "无效的数据格式或缺少参数"})
		return
	}

	if req.QQ == "" || req.Action == "" {
		c.JSON(400, gin.H{"code": 400, "msg": "缺少参数"})
		return
	}

	if !utils.IsValidQQNumber(req.QQ) {
		c.JSON(400, gin.H{"code": 400, "msg": "无效的 QQ 邮箱格式"})
		return
	}

	if !redisClient.CanSendCaptcha(req.QQ) {
		c.JSON(429, gin.H{"code": 429, "msg": "验证码发送过于频繁，请1分钟后再试"})
		return
	}

	// IP 维度全局频率限制：同一 IP 每小时最多 10 次
	clientIP := c.ClientIP()
	if !redisClient.CanSendCaptchaByIP(clientIP, 10) {
		c.JSON(429, gin.H{"code": 429, "msg": "请求过于频繁，请稍后再试"})
		return
	}

	switch req.Action {
	case "register":
		if !cfg.EnableRegister {
			c.JSON(403, gin.H{"code": 403, "msg": "当前已关闭注册功能"})
			return
		}
		captcha := utils.GenerateCaptchaFull()
		redisClient.SetCaptchaForAction(req.QQ, captcha, "register")
		mail.SendCaptcha(fmt.Sprintf("%s@qq.com", req.QQ), captcha)

	case "reset_password":
		// 不暴露 QQ 是否已注册，统一返回成功
		captcha := utils.GenerateCaptchaFull()
		redisClient.SetCaptchaForAction(req.QQ, captcha, "reset_password")
		mail.SendCaptcha(fmt.Sprintf("%s@qq.com", req.QQ), captcha)

	default:
		c.JSON(400, gin.H{"code": 400, "msg": "无效的 action 类型，仅支持 register 和 reset_password"})
		return
	}

	c.JSON(200, gin.H{"code": 200, "msg": "发送成功"})
}

// ResetPasswordHandler POST /api/user/reset_password
// 未登录状态下的密码重置（通过验证码）
func ResetPasswordHandler(c *gin.Context) {
	var req struct {
		QQ          string `json:"qq" binding:"required"`
		Captcha     string `json:"captcha" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式不正确"})
		return
	}

	if len(req.NewPassword) < 6 || len(req.NewPassword) > 32 {
		c.JSON(400, gin.H{"code": 400, "msg": "密码长度必须在 6-32 位之间"})
		return
	}

	if !redisClient.VerifyCaptchaByAction(req.QQ, req.Captcha, "reset_password") {
		c.JSON(400, gin.H{"code": 400, "msg": "验证码错误或已失效"})
		return
	}

	var exists bool
	err := userDao.Pool.QueryRow(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM users WHERE qq = $1)", req.QQ).Scan(&exists)
	if err != nil || !exists {
		c.JSON(400, gin.H{"code": 400, "msg": "验证码错误或已失效"})
		return
	}

	err = userDao.UpdateUserPassword(req.QQ, req.NewPassword)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "密码重置失败，请稍后重试"})
		return
	}

	// 密码重置后清除该用户所有 Session
	redisClient.DeleteUserSessionsByQQ(req.QQ)

	c.JSON(200, gin.H{"code": 200, "msg": "密码修改成功，请使用新密码登录"})
}

// RegisterHandler POST /api/user_register
// 用户注册（需邮箱验证码）
func RegisterHandler(c *gin.Context) {
	if !cfg.EnableRegister {
		c.JSON(403, gin.H{"code": 403, "msg": "当前已关闭注册功能"})
		return
	}

	var req config.UserRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "无效的数据格式或缺少参数"})
		return
	}

	if req.QQ == "" || req.Password == "" || req.Captcha == "" {
		c.JSON(400, gin.H{"code": 400, "msg": "缺少参数"})
		return
	} else if len(req.Password) < 6 || len(req.Password) > 32 {
		c.JSON(400, gin.H{"code": 400, "msg": "密码长度必须在 6-32 位之间"})
		return
	}

	if !utils.IsValidQQNumber(req.QQ) {
		c.JSON(400, gin.H{"code": 400, "msg": "无效的 QQ 邮箱格式"})
		return
	}

	if !redisClient.VerifyCaptchaByAction(req.QQ, req.Captcha, "register") {
		c.JSON(400, gin.H{"code": 400, "msg": "验证码错误或已失效"})
		return
	}

	token, err := userDao.RegisterUser(req.QQ, req.Password)
	if err != nil {
		// 精确判断唯一约束冲突（QQ 已注册），其他错误走 500
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			c.JSON(409, gin.H{"code": 409, "msg": "该 QQ 号已注册"})
			return
		}
		c.JSON(500, gin.H{"code": 500, "msg": "注册失败,请稍后重试"})
		return
	}

	sessionToken := pgsqlOperate.GenerateRandomToken()
	redisClient.SetUserSession(sessionToken, req.QQ, false) // 注册后默认 7 天

	c.JSON(200, gin.H{
		"code": 200,
		"msg":  "注册成功",
		"data": gin.H{
			"session_token": sessionToken,
			"api_token":    token,
			"qq":           req.QQ,
		},
	})
}

// LoginHandler POST /api/user/login
// 用户登录（含失败锁定机制：3 次失败锁定 10 分钟）
func LoginHandler(c *gin.Context) {
	var req struct {
		QQ       string `json:"qq" binding:"required"`
		Password string `json:"password" binding:"required"`
		Remember bool   `json:"remember"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式错误"})
		return
	}

	var passwordHash, token string
	var status int16
	err := userDao.Pool.QueryRow(context.Background(),
		"SELECT password_hash, api_token, status FROM users WHERE qq = $1",
		req.QQ).Scan(&passwordHash, &token, &status)
	if err != nil {
		c.JSON(401, gin.H{"code": 401, "msg": "账号或密码错误"})
		return
	}

	if status == 0 {
		c.JSON(401, gin.H{"code": 401, "msg": "账号或密码错误"})
		return
	}

	// 检查登录失败锁定
	if locked, remainSec := redisClient.CheckLoginLock(req.QQ); locked {
		c.JSON(429, gin.H{
			"code": 429,
			"msg":  fmt.Sprintf("登录失败次数过多，请 %d 分钟后再试", (remainSec+59)/60),
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password))
	if err != nil {
		attempts, _ := redisClient.RecordLoginFail(req.QQ)
		if attempts >= 3 {
			c.JSON(429, gin.H{
				"code": 429,
				"msg":  "登录失败次数过多，请稍后再试",
			})
		} else {
			c.JSON(401, gin.H{
				"code": 401,
				"msg":  "账号或密码错误",
			})
		}
		return
	}

	// 登录成功，清除失败计数
	redisClient.ClearLoginFails(req.QQ)

	sessionToken := pgsqlOperate.GenerateRandomToken()
	redisClient.SetUserSession(sessionToken, req.QQ, req.Remember)

	c.JSON(200, gin.H{
		"code": 200,
		"msg":  "登录成功",
		"data": gin.H{
			"session_token": sessionToken,
			"api_token": token,
			"qq":        req.QQ,
		},
	})
}

// UseCDKHandler POST /api/user_use_cdk
// 用户兑换 CDK 卡密
func UseCDKHandler(c *gin.Context) {
	sessionToken := c.GetHeader("X-Session-Token")
	if sessionToken == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "未登录"})
		return
	}

	var req struct { CDK string `json:"cdk"` }
	if err := c.ShouldBindJSON(&req); err != nil || req.CDK == "" {
		c.JSON(400, gin.H{"code": 400, "msg": "请输入有效的卡密"})
		return
	}

	qq, err := redisClient.GetUserSession(sessionToken)
	if err != nil || qq == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "登录已过期，请重新登录"})
		return
	}

	msg, err := userDao.UseCDKCard(qq, req.CDK)
	if err != nil {
		c.JSON(200, gin.H{"code": 400, "msg": msg})
		return
	}

	c.JSON(200, gin.H{"code": 200, "msg": msg})
}

// GetUserInfoHandler GET /api/user/me
// 获取当前登录用户信息（含资产列表 + 注册时间 + 每日上限）
func GetUserInfoHandler(c *gin.Context) {
	sessionToken := c.GetHeader("X-Session-Token")
	if sessionToken == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "未登录"})
		return
	}

	qq, err := redisClient.GetUserSession(sessionToken)
	if err != nil || qq == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "登录已过期，请重新登录"})
		return
	}

	var realApiToken string
	var status int16
	var createdAt time.Time
	err = userDao.Pool.QueryRow(context.Background(),
		"SELECT api_token, status, created_at FROM users WHERE qq = $1",
		qq).Scan(&realApiToken, &status, &createdAt)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "查询用户信息失败"})
		return
	}

	rows, err := userDao.Pool.Query(context.Background(),
		"SELECT api_name, daily_limit, max_daily_limit, extra_balance, has_permission FROM user_api_assets WHERE qq = $1", qq)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "查询资产失败"})
		return
	}
	defer rows.Close()

	var assets []map[string]interface{}
	for rows.Next() {
		var apiName string
		var dailyLimit, maxDailyLimit, extraBalance int
		var hasPerm bool
		rows.Scan(&apiName, &dailyLimit, &maxDailyLimit, &extraBalance, &hasPerm)
		assets = append(assets, map[string]interface{}{
			"api_name":        apiName,
			"daily_limit":     dailyLimit,
			"max_daily_limit": maxDailyLimit,
			"extra_balance":   extraBalance,
			"has_permission":  hasPerm,
		})
	}

	c.JSON(200, gin.H{
		"code": 200,
		"data": gin.H{
			"qq":         qq,
			"status":     fmt.Sprintf("%d", status),
			"created_at": createdAt.Format("2006-01-02"),
			"assets":     assets,
			"api_key":    realApiToken,
		},
	})
}

// ChangePasswordHandler POST /api/user/change-password
// 已登录用户修改密码（需验证旧密码）
func ChangePasswordHandler(c *gin.Context) {
	sessionToken := c.GetHeader("X-Session-Token")
	if sessionToken == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "未登录"})
		return
	}

	qq, err := redisClient.GetUserSession(sessionToken)
	if err != nil || qq == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "登录已过期，请重新登录"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式不正确"})
		return
	}

	if len(req.NewPassword) < 6 || len(req.NewPassword) > 32 {
		c.JSON(400, gin.H{"code": 400, "msg": "新密码长度必须在 6-32 位之间"})
		return
	}

	if req.OldPassword == req.NewPassword {
		c.JSON(400, gin.H{"code": 400, "msg": "新密码不能与旧密码相同"})
		return
	}

	var passwordHash string
	err = userDao.Pool.QueryRow(context.Background(),
		"SELECT password_hash FROM users WHERE qq = $1", qq).Scan(&passwordHash)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "查询用户信息失败"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.OldPassword))
	if err != nil {
		c.JSON(401, gin.H{"code": 401, "msg": "旧密码错误"})
		return
	}

	err = userDao.UpdateUserPassword(qq, req.NewPassword)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "密码修改失败，请稍后重试"})
		return
	}

	// 密码修改成功后清除该用户所有 Session，强制重新登录
	redisClient.DeleteUserSessionsByQQ(qq)

	c.JSON(200, gin.H{"code": 200, "msg": "密码修改成功，请重新登录"})
}

// RegenTokenHandler POST /api/user/regen_token
// 用户重新生成自己的 API Token
func RegenTokenHandler(c *gin.Context) {
	sessionToken := c.GetHeader("X-Session-Token")
	if sessionToken == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "未登录"})
		return
	}

	qq, err := redisClient.GetUserSession(sessionToken)
	if err != nil || qq == "" {
		c.JSON(401, gin.H{"code": 401, "msg": "登录已过期，请重新登录"})
		return
	}

	newToken, err := userDao.RegenUserApiToken(qq)
	if err != nil {
		fmt.Printf("[User] 重置Token失败: %v\n", err)
		c.JSON(500, gin.H{"code": 500, "msg": "重置失败，请稍后重试"})
		return
	}

	c.JSON(200, gin.H{
		"code": 200,
		"msg":  "API Token 已重新生成（旧 Token 立即失效）",
		"data": gin.H{
			"new_token": newToken,
			"qq":        qq,
		},
	})
}

// AdminLoginHandler POST /api/admin/login
// 管理员登录（比对配置文件中的账号密码）
func AdminLoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"msg": "参数格式错误"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Username), []byte(cfg.Admin.Username)) != 1 ||
		subtle.ConstantTimeCompare([]byte(req.Password), []byte(cfg.Admin.Password)) != 1 {
		c.JSON(401, gin.H{"msg": "管理员账号或密码错误"})
		return
	}

	sessionToken := pgsqlOperate.GenerateRandomToken()
	err := redisClient.SetAdminSession(sessionToken, req.Username, 2*time.Hour)
	if err != nil {
		c.JSON(500, gin.H{"msg": "Session 创建失败"})
		return
	}

	c.JSON(200, gin.H{
		"code":        200,
		"msg":         "登录成功",
		"admin_token": sessionToken,
	})
}
