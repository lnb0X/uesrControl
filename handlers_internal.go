package main

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"userControl/func/utils"
)

// RegisterInternalRoutes 注册内部服务间调用路由
// 使用 InternalServerMiddleware 鉴权（X-Server-Secret）
func RegisterInternalRoutes(rg *gin.RouterGroup) {
	internal := rg.Group("/internal")
	internal.Use(InternalServerMiddleware(cfg.InternalSecret))
	{
		internal.POST("/user/set_status", internalSetUserStatus)
		internal.POST("/check_quota", internalCheckQuota)
		internal.POST("/consume", internalConsume)
		internal.POST("/generate_cdk", internalGenerateCDK)
	}
}

// ============================================================
//  内部服务 handlers
// ============================================================

// internalSetUserStatus 修改用户身份状态
func internalSetUserStatus(c *gin.Context) {
	var req struct {
		QQ     string `json:"qq" binding:"required"`
		Status int16  `json:"status"` // 1:普通, 2:VIP, 3:SVIP, 4:书源用户, 0:封禁
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式不正确"})
		return
	}

	err := userDao.UpdateUserStatus(req.QQ, req.Status)
	if err != nil {
		c.JSON(500, gin.H{"code": 500, "msg": "修改用户状态失败: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{"code": 200, "msg": "用户身份已成功更新"})
}

// internalCheckQuota 查询用户的 API 配额详情
func internalCheckQuota(c *gin.Context) {
	var req struct {
		Token   string `json:"token" binding:"required"`
		ApiName string `json:"api_name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数错误"})
		return
	}

	detail, statusCode, err := userDao.GetUserQuotaDetail(req.Token, req.ApiName)
	if err != nil {
		c.JSON(statusCode, gin.H{"code": statusCode, "msg": err.Error()})
		return
	}

	// 安全类型断言，避免未来 DAO 层变更导致 panic
	dailyLimit, _ := detail["daily_limit"].(int)
	extraBalance, _ := detail["extra_balance"].(int)

	c.JSON(200, gin.H{
		"code":         200,
		"msg":          "成功",
		"data":         detail,
		"need_confirm": dailyLimit <= 0 && extraBalance > 0,
	})
}

// internalConsume 扣除用户 API 配额
// 免费额度不足时返回 402，需要用户授权扣付费余额
func internalConsume(c *gin.Context) {
	var req struct {
		Token      string `json:"token" binding:"required"`
		ApiName    string `json:"api_name" binding:"required"`
		Cost       int    `json:"cost"`
		AllowExtra bool   `json:"allow_extra"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式不正确"})
		return
	}

	if req.Cost <= 0 {
		req.Cost = 1
	}

	success, err := userDao.DeductApiQuotaSecure(req.Token, req.ApiName, req.Cost, req.AllowExtra)

	if !success {
		if err.Error() == "免费额度不足，需要用户授权扣除付费余额" {
			c.JSON(402, gin.H{
				"code":         402,
				"msg":          err.Error(),
				"need_confirm": true,
			})
			return
		}

		c.JSON(403, gin.H{"code": 403, "msg": err.Error()})
		return
	}

	c.JSON(200, gin.H{"code": 200, "msg": "扣费成功"})
}

// internalGenerateCDK 内部服务生成 CDK 卡密
// 与 admin 的 CDK 生成逻辑相同，但走内部鉴权通道
func internalGenerateCDK(c *gin.Context) {
	var req struct {
		ScopeType  int16  `json:"scope_type"`  // 1:指定QQ, 2:指定身份, 3:全网通用
		ScopeValue string `json:"scope_value"` // 具体QQ号或身份ID
		CardType   int16  `json:"card_type"`   // 1:充值余额(E), 2:增加每日上限(L), 3:开通权限
		ApiName    string `json:"api_name"`    // 作用于哪个API
		FaceValue  int    `json:"face_value"`  // 面值(充值多少)
		DaysValid  int    `json:"days_valid"`  // 有效期(天)
		MaxUses    int    `json:"max_uses"`    // 最大使用次数，0=不限
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"code": 400, "msg": "参数格式不正确"})
		return
	}

	if req.DaysValid <= 0 {
		req.DaysValid = 30 // 默认 30 天
	}
	if req.FaceValue <= 0 && req.CardType != 3 {
		c.JSON(400, gin.H{"code": 400, "msg": "面额必须大于0"})
		return
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
		return
	}

	err = userDao.CreateCDK(cdkStr, req.ScopeType, req.ScopeValue,
		req.CardType, req.ApiName, req.FaceValue, expireTime, req.MaxUses)
	if err != nil {
		fmt.Printf("[Internal] CDK写入失败: %v\n", err)
		c.JSON(500, gin.H{"code": 500, "msg": "生成失败，请稍后重试"})
		return
	}

	c.JSON(200, gin.H{
		"code": 200,
		"msg":  "卡密生成成功",
		"data": gin.H{
			"cdk":        cdkStr,
			"expires_at": expireTime.Format("2006-01-02 15:04:05"),
		},
	})
}
