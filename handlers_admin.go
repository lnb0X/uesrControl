package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"userControl/config"
	"userControl/func/mail"
	"userControl/func/pgsqlOperate"
	"userControl/func/utils"
)

// RegisterAdminRoutes 注册所有需要管理员鉴权的路由
// 使用 AdminAuthMiddleware 中间件，通过 Admin-Token Header 鉴权
func RegisterAdminRoutes(rg *gin.RouterGroup) {
	admin := rg.Group("/admin")
	admin.Use(AdminAuthMiddleware(redisClient))
	{
		// --- 用户管理 ---

		// 获取用户列表（支持分页 + 多条件筛选）
		admin.GET("/users", adminGetUsers)

		// 修改用户状态
		admin.POST("/user/set_status", adminSetUserStatus)

		// 修改用户 API 限额
		admin.POST("/user/set_limit", adminSetUserLimit)

		// 管理员重置用户密码
		admin.POST("/user/reset_password", adminResetUserPassword)

		// 管理员重新生成用户的 API Token
		admin.POST("/user/regen_token", adminRegenUserToken)

		// 删除用户的特定接口资产
		admin.DELETE("/user/asset", adminDeleteUserAsset)

		// 彻底删除用户
		admin.DELETE("/user", adminDeleteUser)

		// --- CDK 管理 ---

		// 获取卡密仓库列表（分页）
		admin.GET("/cdks", adminGetCDKs)

		// 作废卡密
		admin.DELETE("/cdk/revoke", adminRevokeCDK)

		// 生成单张 CDK
		admin.POST("/generate_cdk", adminGenerateCDK)

		// 批量生成 CDK
		admin.POST("/generate_cdk_batch", adminGenerateCDKBatch)

		// --- 仪表盘与配置 ---

		// 仪表盘统计
		admin.GET("/dashboard/stats", adminDashboardStats)

		// 获取当前系统配置
		admin.GET("/config", adminGetConfig)

		// 获取配置明文（需验证管理员密码）
		admin.POST("/config/reveal", adminRevealConfig)

		// 更新系统配置（热更新）
		admin.POST("/config", adminUpdateConfig)
	}
}

// ============================================================
//  用户管理 handlers
// ============================================================

func adminGetUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	offset := (page - 1) * size

	filter := pgsqlOperate.UserFilter{
		QQ:      c.Query("qq"),
		Status:  c.Query("status"),
		HasApi:  c.Query("has_api"),
		ApiName: c.Query("api_name"),
	}
	if v, err := strconv.Atoi(c.Query("min_cards")); err == nil {
		filter.MinCards = v
	}
	if v, err := strconv.Atoi(c.Query("max_cards")); err == nil {
		filter.MaxCards = v
	}

	users, total, err := userDao.GetAllUsers(size, offset, filter)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "获取失败"})
		return
	}
	c.JSON(200, gin.H{"code": 200, "data": users, "total": total})
}

func adminSetUserStatus(c *gin.Context) {
	var req struct {
		QQ     string `json:"qq" binding:"required"`
		Status int16  `json:"status"` // 1:正常, 2:VIP, 0:封禁
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"msg": "缺少必要参数 (qq)"})
		return
	}
	if req.Status < 0 || req.Status > 3 {
		c.JSON(400, gin.H{"msg": "无效的状态值 (0:封禁, 1:正常, 2:VIP, 3:SVIP)"})
		return
	}
	err := userDao.UpdateUserStatus(req.QQ, req.Status)
	if err != nil {
		c.JSON(500, gin.H{"msg": "修改失败: " + err.Error()})
		return
	}

	// 封禁用户时清除其所有 Session，使其立即下线
	if req.Status == 0 {
		redisClient.DeleteUserSessionsByQQ(req.QQ)
	}

	c.JSON(200, gin.H{"msg": "设置成功"})
}

func adminSetUserLimit(c *gin.Context) {
	var req struct {
		QQ         string `json:"qq" binding:"required"`
		ApiName    string `json:"api_name" binding:"required"`
		DailyLimit int    `json:"daily_limit"`
		HasPerm    bool   `json:"has_perm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"msg": "缺少必要参数 (qq, api_name)"})
		return
	}
	if req.DailyLimit < 0 {
		c.JSON(400, gin.H{"msg": "每日额度不能为负数"})
		return
	}
	err := userDao.UpdateUserApiLimit(req.QQ, req.ApiName, req.DailyLimit, req.HasPerm)
	if err != nil {
		c.JSON(500, gin.H{"msg": "修改失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"msg": "限额修改成功"})
}

func adminResetUserPassword(c *gin.Context) {
	var req struct {
		QQ          string `json:"qq" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"msg": "参数错误"})
		return
	}
	if len(req.NewPassword) < 6 {
		c.JSON(400, gin.H{"msg": "密码太短"})
		return
	}
	err := userDao.UpdateUserPassword(req.QQ, req.NewPassword)
	if err != nil {
		c.JSON(500, gin.H{"msg": "修改失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"code": 200, "msg": "密码已成功重置"})
}

func adminRegenUserToken(c *gin.Context) {
	var req struct { QQ string `json:"qq" binding:"required"` }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数错误"})
		return
	}
	newToken, err := userDao.RegenUserApiToken(req.QQ)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "重置失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"code": 200,
		"msg":  "API Token 已重新生成（旧 Token 立即失效）",
		"data": gin.H{"new_token": newToken, "qq": req.QQ},
	})
}

func adminDeleteUserAsset(c *gin.Context) {
	qq := c.Query("qq")
	apiName := c.Query("api_name")
	if qq == "" || apiName == "" {
		c.JSON(400, gin.H{"msg": "缺少参数"})
		return
	}
	err := userDao.DeleteUserApiAsset(qq, apiName)
	if err != nil {
		c.JSON(500, gin.H{"msg": "删除失败: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"code": 200, "msg": "接口资产已彻底删除"})
}

func adminDeleteUser(c *gin.Context) {
	qq := c.Query("qq")
	if qq == "" {
		c.JSON(400, gin.H{"msg": "缺少 QQ 参数"})
		return
	}
	err := userDao.DeleteUser(qq)
	if err != nil {
		fmt.Printf("[Admin] 删除用户失败: %v\n", err)
		c.JSON(500, gin.H{"msg": "删除失败，请稍后重试"})
		return
	}
	c.JSON(200, gin.H{"code": 200, "msg": "用户已彻底删除"})
}

// ============================================================
//  CDK 管理 handlers
// ============================================================

func adminGetCDKs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
	offset := (page - 1) * size

	cdks, total, err := userDao.GetAllCDKs(size, offset)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "获取失败"})
		return
	}
	c.JSON(200, gin.H{"code": 200, "data": cdks, "total": total})
}

func adminRevokeCDK(c *gin.Context) {
	cardKey := c.Query("card_key")
	err := userDao.RevokeCDK(cardKey)
	if err != nil {
		c.JSON(500, gin.H{"msg": "作废失败"})
		return
	}
	c.JSON(200, gin.H{"msg": "该卡密已从池中移除"})
}

// generateCDKFromRequest 公共逻辑：从请求体构造并写入一张 CDK
// 同时返回生成的卡密字符串和过期时间，供 handler 统一返回格式
func generateCDKFromRequest(c *gin.Context) (string, time.Time, bool) {
	var req struct {
		ScopeType  int16  `json:"scope_type"`
		ScopeValue string `json:"scope_value"`
		CardType   int16  `json:"card_type"`
		ApiName    string `json:"api_name"`
		FaceValue  int    `json:"face_value"`
		DaysValid  int    `json:"days_valid"`
		MaxUses    int    `json:"max_uses"` // 最大使用次数，0=不限
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式错误"})
		return "", time.Time{}, false
	}

	if req.DaysValid <= 0 {
		req.DaysValid = 30
	}
	if req.FaceValue <= 0 && req.CardType != 3 {
		c.JSON(400, gin.H{"code": 400, "msg": "面额必须大于0"})
		return "", time.Time{}, false
	}
	if req.MaxUses < 0 {
		req.MaxUses = 0
	}

	expireTime := time.Now().AddDate(0, 0, req.DaysValid)
	randomTag := utils.GenerateCaptchaFull()

	payload := utils.CdkData{
		ScopeType:  req.ScopeType,
		ScopeValue: req.ScopeValue,
		CardType:   req.CardType,
		ApiName:    req.ApiName,
		FaceValue:  req.FaceValue,
		ExpiresAt:  expireTime.Unix(),
		MaxUses:    req.MaxUses,
		RandTag:    randomTag,
	}

	cdkStr, err := utils.EncryptCDK(payload)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "卡密生成失败"})
		return "", time.Time{}, false
	}

	err = userDao.CreateCDK(cdkStr, req.ScopeType, req.ScopeValue, req.CardType,
		req.ApiName, req.FaceValue, expireTime, req.MaxUses)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "数据库写入失败: " + err.Error()})
		return "", time.Time{}, false
	}

	return cdkStr, expireTime, true
}

func adminGenerateCDK(c *gin.Context) {
	cdkStr, expireTime, ok := generateCDKFromRequest(c)
	if !ok {
		return
	}
	c.JSON(200, gin.H{
		"code": 200,
		"msg":  "生成成功",
		"data": gin.H{
			"cdk":        cdkStr,
			"expires_at": expireTime.Format("2006-01-02 15:04:05"),
		},
	})
}

func adminGenerateCDKBatch(c *gin.Context) {
	var req struct {
		ScopeType  int16  `json:"scope_type"`
		ScopeValue string `json:"scope_value"`
		CardType   int16  `json:"card_type"`
		ApiName    string `json:"api_name"`
		FaceValue  int    `json:"face_value"`
		DaysValid  int    `json:"days_valid"`
		MaxUses    int    `json:"max_uses"` // 最大使用次数，0=不限
		Count      int    `json:"count"`    // 默认1，最大100
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式错误"})
		return
	}

	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 100 {
		c.JSON(400, gin.H{"code": 400, "msg": "单次生成数量不能超过 100 张"})
		return
	}
	if req.DaysValid <= 0 {
		req.DaysValid = 30
	}
	if req.FaceValue <= 0 && req.CardType != 3 {
		c.JSON(400, gin.H{"code": 400, "msg": "面额必须大于0"})
		return
	}
	if req.MaxUses < 0 {
		req.MaxUses = 0
	}

	expireTime := time.Now().AddDate(0, 0, req.DaysValid)
	var results []gin.H

	for i := 0; i < req.Count; i++ {
		randomTag := utils.GenerateCaptchaFull()
		payload := utils.CdkData{
			ScopeType:  req.ScopeType,
			ScopeValue: req.ScopeValue,
			CardType:   req.CardType,
			ApiName:    req.ApiName,
			FaceValue:  req.FaceValue,
			ExpiresAt:  expireTime.Unix(),
			MaxUses:    req.MaxUses,
			RandTag:    randomTag,
		}

		cdkStr, err := utils.EncryptCDK(payload)
		if err != nil {
			continue
		}

		err = userDao.CreateCDK(cdkStr, req.ScopeType, req.ScopeValue,
			req.CardType, req.ApiName, req.FaceValue, expireTime, req.MaxUses)
		if err != nil {
			continue
		}

		results = append(results, gin.H{
			"cdk":        cdkStr,
			"expires_at": expireTime.Format("2006-01-02 15:04:05"),
		})
	}

	if len(results) == 0 {
		c.JSON(500, gin.H{"code": 500, "msg": "全部生成失败"})
		return
	}

	c.JSON(200, gin.H{
		"code": 200,
		"msg":  fmt.Sprintf("成功生成 %d 张卡密", len(results)),
		"data": gin.H{"list": results, "total": len(results)},
	})
}

// ============================================================
//  仪表盘 & 配置 handlers
// ============================================================

func adminDashboardStats(c *gin.Context) {
	ctx := context.Background()

	// 用户统计
	var totalUsers, todayUsers, vipCount, svipCount, bannedCount int
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&totalUsers)
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE").Scan(&todayUsers)
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE status = 2").Scan(&vipCount)
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE status = 3").Scan(&svipCount)
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE status = 0").Scan(&bannedCount)

	// CDK 统计
	var totalCDK, unusedCDK, usedCDK, expiredCDK, todayRedeemed int
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cdk_cards").Scan(&totalCDK)
	// 未使用：未过期 且 使用次数未达上限（max_uses=0 不限次数，视为可用；max_uses>0 且 used_count<max_uses 视为可用）
	userDao.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM cdk_cards c
		WHERE c.expires_at > NOW()
		  AND (c.max_uses = 0 OR c.max_uses > (SELECT COUNT(*) FROM user_cdk_usage u WHERE u.card_key = c.card_key))
	`).Scan(&unusedCDK)
	userDao.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM cdk_cards c
		WHERE c.max_uses > 0 AND (SELECT COUNT(*) FROM user_cdk_usage u WHERE u.card_key = c.card_key) >= c.max_uses
	`).Scan(&usedCDK)
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cdk_cards WHERE expires_at <= NOW()").Scan(&expiredCDK)
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM user_cdk_usage WHERE qq IS NOT NULL AND card_key IN (SELECT card_key FROM cdk_cards WHERE created_at >= CURRENT_DATE)").Scan(&todayRedeemed)

	// 接口资产统计
	var totalAssets int
	userDao.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM user_api_assets WHERE has_permission = TRUE").Scan(&totalAssets)

	c.JSON(200, gin.H{
		"code": 200,
		"data": gin.H{
			"users": gin.H{
				"total":       totalUsers,
				"today_new":   todayUsers,
				"vip_count":   vipCount,
				"svip_count":  svipCount,
				"banned_count": bannedCount,
			},
			"cdk": gin.H{
				"total":         totalCDK,
				"unused":        unusedCDK,
				"used":          usedCDK,
				"expired":       expiredCDK,
				"today_redeemed": todayRedeemed,
			},
			"assets": gin.H{
				"total_active": totalAssets,
			},
		},
	})
}

// adminGetConfig GET /api/admin/config
// 返回配置信息，敏感字段脱敏显示
func adminGetConfig(c *gin.Context) {
	cfg := config.Get()

	data := gin.H{
		"server": gin.H{
			"port": cfg.Server.Port,
			"mode": cfg.Server.Mode,
		},
		"enable_register": cfg.EnableRegister,
		"postgres": gin.H{
			"user":     cfg.Postgres.User,
			"password": "******",
			"host":     cfg.Postgres.Host,
			"database": cfg.Postgres.DBName,
			"sslmode":  cfg.Postgres.SSLMode,
		},
		"redis": gin.H{
			"addr":     cfg.Redis.Addr,
			"password": "******",
			"db":       cfg.Redis.DB,
		},
		"admin": gin.H{
			"username": cfg.Admin.Username,
			"password": "******",
		},
		"email": gin.H{
			"from":     cfg.Email.From,
			"password": "******",
			"host":     cfg.Email.Host,
			"port":     cfg.Email.Port,
		},
		"internal_secret": "******",
	}

	c.JSON(200, gin.H{
		"code": 200,
		"data": data,
	})
}

// adminRevealConfig POST /api/admin/config/reveal
// 验证管理员密码后返回完整明文配置
func adminRevealConfig(c *gin.Context) {
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "请输入管理员密码"})
		return
	}

	cfg := config.Get()
	if subtle.ConstantTimeCompare([]byte(req.Password), []byte(cfg.Admin.Password)) != 1 {
		c.JSON(403, gin.H{"code": 403, "msg": "管理员密码错误"})
		return
	}

	data := gin.H{
		"server": gin.H{
			"port": cfg.Server.Port,
			"mode": cfg.Server.Mode,
		},
		"enable_register": cfg.EnableRegister,
		"postgres": gin.H{
			"user":     cfg.Postgres.User,
			"password": cfg.Postgres.Password,
			"host":     cfg.Postgres.Host,
			"database": cfg.Postgres.DBName,
			"sslmode":  cfg.Postgres.SSLMode,
		},
		"redis": gin.H{
			"addr":     cfg.Redis.Addr,
			"password": cfg.Redis.Password,
			"db":       cfg.Redis.DB,
		},
		"admin": gin.H{
			"username": cfg.Admin.Username,
			"password": cfg.Admin.Password,
		},
		"email": gin.H{
			"from":     cfg.Email.From,
			"password": cfg.Email.Password,
			"host":     cfg.Email.Host,
			"port":     cfg.Email.Port,
		},
		"internal_secret": cfg.InternalSecret,
	}

	c.JSON(200, gin.H{
		"code": 200,
		"data": data,
	})
}

func adminUpdateConfig(c *gin.Context) {
	var updates map[string]interface{}
	if err := c.ShouldBindJSON(&updates); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式错误"})
		return
	}

	if err := config.UpdatePartial(updates); err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "保存配置失败: " + err.Error()})
		return
	}

	// 热更新：重新加载到内存
	cfg = config.Load()
	mail.CFG = &cfg.Email

	c.JSON(200, gin.H{"code": 200, "msg": "配置已保存并立即生效"})
}
