package main

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	redisOperate "userControl/func/redis"
)

// SecurityHeadersMiddleware 为所有响应添加安全相关 HTTP 头
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 防止 MIME 嗅探，浏览器必须遵循服务器声明的 Content-Type
		c.Header("X-Content-Type-Options", "nosniff")
		// 防止页面被 iframe 嵌入（防点击劫持）
		c.Header("X-Frame-Options", "DENY")
		// 启用浏览器内置 XSS 过滤（老浏览器适用，现代浏览器默认开启）
		c.Header("X-XSS-Protection", "1; mode=block")
		// 控制 Referrer 信息泄露
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// AdminAuthMiddleware 管理端 Session 鉴权中间件
// 从 Header 获取 Admin-Token，去 Redis 校验有效性
func AdminAuthMiddleware(rdb *redisOperate.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Admin-Token")
		if token == "" {
			c.AbortWithStatusJSON(401, gin.H{"code": 401, "msg": "管理端未登录"})
			return
		}

		exists, err := rdb.CheckAdminSession(token)
		if err != nil || !exists {
			// 无效/过期 token 属于认证失败，返回 401 而非 403
			c.AbortWithStatusJSON(401, gin.H{"code": 401, "msg": "Session 已过期，请重新登录"})
			return
		}
		c.Next()
	}
}

// InternalServerMiddleware 内部服务间调用的鉴权中间件
// 要求请求头携带 X-Server-Secret，与配置中的 InternalSecret 一致才放行
// 缺失或错误均返回 401（未认证），符合 HTTP 标准
func InternalServerMiddleware(serverSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientSecret := c.GetHeader("X-Server-Secret")
		if clientSecret == "" || subtle.ConstantTimeCompare([]byte(clientSecret), []byte(serverSecret)) != 1 {
			c.AbortWithStatusJSON(401, gin.H{
				"code": 401,
				"msg":  "非法的内部调用",
			})
			return
		}
		c.Next()
	}
}

// AdminLoginRateLimit 管理员登录限速中间件（防暴力破解）
// 策略：同一 IP 每 15 分钟最多尝试 5 次
func AdminLoginRateLimit() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 15 * time.Minute,
		Limit:  int64(5),
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)

	return func(c *gin.Context) {
		identifier := c.ClientIP()

		ctx, err := instance.Get(c, identifier)
		if err != nil {
			fmt.Printf("[警告] 限速器异常: %v\n", err)
			c.Next()
			return
		}

		c.Header("X-RateLimit-Limit", strconv.FormatInt(ctx.Limit, 10))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(ctx.Remaining, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(ctx.Reset, 10))

		if ctx.Reached {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code": 429,
				"msg":  fmt.Sprintf("登录失败次数过多，请 %d 分钟后再试 (限制: 5次/15分钟)", int(15*time.Minute/time.Minute)),
			})
			return
		}
		c.Next()
	}
}

// PublicApiRateLimit 公开接口通用限速中间件
// 策略：同一 IP 每小时最多 20 次请求（注册、重置密码等）
func PublicApiRateLimit() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 1 * time.Hour,
		Limit:  int64(20),
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)

	return func(c *gin.Context) {
		identifier := c.ClientIP()

		ctx, err := instance.Get(c, identifier)
		if err != nil {
			fmt.Printf("[警告] 限速器异常: %v\n", err)
			c.Next()
			return
		}

		if ctx.Reached {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code": 429,
				"msg":  "请求过于频繁，请稍后再试",
			})
			return
		}
		c.Next()
	}
}

// UserLoginRateLimit 用户登录限速中间件（防暴力破解）
// 策略：同一 IP 每 15 分钟最多尝试 10 次（比管理员宽松，用户量更大）
func UserLoginRateLimit() gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 15 * time.Minute,
		Limit:  int64(10),
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)

	return func(c *gin.Context) {
		identifier := c.ClientIP()

		ctx, err := instance.Get(c, identifier)
		if err != nil {
			fmt.Printf("[警告] 限速器异常: %v\n", err)
			c.Next()
			return
		}

		if ctx.Reached {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code": 429,
				"msg":  "登录请求过于频繁，请 15 分钟后再试",
			})
			return
		}
		c.Next()
	}
}
