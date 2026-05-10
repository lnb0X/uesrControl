package main

import (
	"github.com/gin-gonic/gin"
)

// RegisterRoutes 注册所有路由到 Gin Engine
// 按权限层级分为三组：
//   - 公开 API（/api/*）— 无需鉴权或用户 Session
//   - 内部服务（/internal/*）— X-Server-Secret 鉴权
//   - 管理后台（/api/admin/*）— Admin-Token 鉴权（在 RegisterAdminRoutes 内部）
func RegisterRoutes(r *gin.Engine) {
	// 全局安全头中间件
	r.Use(SecurityHeadersMiddleware())

	// 静态页面
	r.StaticFile("/admin", "./admin.html")
	r.StaticFile("/user", "./user_dashboard.html")

	api := r.Group("/api")
	api.Use() // 预留全局中间件位置

	// ====== 无需登录的公开接口 ======
	{
		api.Handle("POST", "/send_captcha", SendCaptchaHandler)

		publicWrite := api.Group("")
		publicWrite.Use(PublicApiRateLimit())
		publicWrite.POST("/user/register", RegisterHandler)
		publicWrite.POST("/user/reset_password", ResetPasswordHandler)

		userLogin := api.Group("")
		userLogin.Use(UserLoginRateLimit())
		userLogin.POST("/user/login", LoginHandler)

		adminLogin := api.Group("")
		adminLogin.Use(AdminLoginRateLimit())
		adminLogin.POST("/admin/login", AdminLoginHandler)
	}

	// ====== 需要用户 Session 的接口 ======
	{
		api.POST("/user/regen_token", RegenTokenHandler)
		api.POST("/user_use_cdk", UseCDKHandler)
		api.GET("/user/me", GetUserInfoHandler)
		api.POST("/user/change-password", ChangePasswordHandler)
	}

	// ====== 内部服务接口（/internal/*，Server Secret 鉴权）=====
	RegisterInternalRoutes(r.Group(""))

	// ====== 管理员接口（Session 鉴权，内部再分组）=====
	RegisterAdminRoutes(api)

	// 通用路由
	r.GET("/ping", ping)
	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{"code": 404, "msg": "Not Found"})
	})
}
