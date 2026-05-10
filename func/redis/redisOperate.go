package redisOperate

import (
	"time"
	"strings"
)

const (
	captchaPrefix = "captcha:"
	captchaTTL    = 5 * time.Minute
)

func (c *Client) SetCaptcha(qq, code string) error {
	key := captchaPrefix + qq
	return c.rdb.Set(c.ctx, key, code, captchaTTL).Err()
}

// SetCaptchaForAction 按 action 类型隔离验证码，防止跨用途复用
func (c *Client) SetCaptchaForAction(qq, code, action string) error {
	key := captchaPrefix + ":" + action + ":" + qq
	return c.rdb.Set(c.ctx, key, code, captchaTTL).Err()
}

func (c *Client) GetCaptcha(qq string) (string, error) {
	key := captchaPrefix + qq

	pipe := c.rdb.Pipeline()
	getCmd := pipe.Get(c.ctx, key)
	pipe.Del(c.ctx, key)

	if _, err := pipe.Exec(c.ctx); err != nil {
		return "", err
	}

	return getCmd.Val(), nil
}

// VerifyCaptchaByAction 验证指定 action 的验证码（防跨用途）
func (c *Client) VerifyCaptchaByAction(qq, inputCode, action string) bool {
	key := captchaPrefix + ":" + action + ":" + qq

	// 用 pipeline 实现 Get + Del 原子操作
	pipe := c.rdb.Pipeline()
	getCmd := pipe.Get(c.ctx, key)
	pipe.Del(c.ctx, key)
	if _, err := pipe.Exec(c.ctx); err != nil {
		return false
	}

	storedCode, err := getCmd.Result()
	if err != nil {
		return false
	}
	
	return strings.EqualFold(storedCode, inputCode)
}

func (c *Client) VerifyCaptcha(qq, inputCode string) bool {
	storedCode, err := c.GetCaptcha(qq)
	if err != nil {
		return false
	}

	return strings.EqualFold(storedCode, inputCode)
}

func (c *Client) CanSendCaptcha(qq string) bool {
	key := "captcha:limit:" + qq

	ok, err := c.rdb.SetNX(c.ctx, key, 1, time.Minute).Result()
	if err != nil {
		return false
	}
	return ok
}

// CanSendCaptchaByIP 检查同一 IP 发送验证码的全局频率
// 限制：同一 IP 每小时最多发送 maxCount 次验证码
func (c *Client) CanSendCaptchaByIP(ip string, maxCount int64) bool {
	key := "captcha:ip:" + ip

	count, err := c.rdb.Incr(c.ctx, key).Result()
	if err != nil {
		return false
	}
	// 首次写入时设置过期时间
	if count == 1 {
		c.rdb.Expire(c.ctx, key, time.Hour)
	}
	return count <= maxCount
}

const (
	userSessionPrefix = "user_session:"
	userSessionTTL    = 7 * 24 * time.Hour // 7天，避免频繁重新登录
)

// 设置普通用户的登录 Session
// remember=true 时 TTL 延长为 30 天，否则默认 7 天
func (c *Client) SetUserSession(sessionToken, qq string, remember bool) error {
	key := userSessionPrefix + sessionToken
	ttl := userSessionTTL
	if remember {
		ttl = 30 * 24 * time.Hour // 记住登录：30 天
	}
	return c.rdb.Set(c.ctx, key, qq, ttl).Err()
}

// 获取普通用户的登录 Session
func (c *Client) GetUserSession(sessionToken string) (string, error) {
	key := userSessionPrefix + sessionToken
	return c.rdb.Get(c.ctx, key).Result()
}

// 删除普通用户的登录 Session (登出用)
func (c *Client) DeleteUserSession(sessionToken string) error {
	key := userSessionPrefix + sessionToken
	return c.rdb.Del(c.ctx, key).Err()
}

// DeleteUserSessionsByQQ 删除指定 QQ 的所有用户 Session（改密码/封禁时使用）
// 通过扫描 user_session:* 匹配值为 qq 的键来删除
func (c *Client) DeleteUserSessionsByQQ(qq string) error {
	var cursor uint64
	var delKeys []string

	for {
		keys, nextCursor, err := c.rdb.Scan(c.ctx, cursor, userSessionPrefix+"*", 100).Result()
		if err != nil {
			return err
		}

		for _, key := range keys {
			val, err := c.rdb.Get(c.ctx, key).Result()
			if err == nil && val == qq {
				delKeys = append(delKeys, key)
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	if len(delKeys) > 0 {
		return c.rdb.Del(c.ctx, delKeys...).Err()
	}
	return nil
}

func (c *Client) SetAdminSession(token, username string, ttl time.Duration) error {
	key := "admin_session:" + token
	return c.rdb.Set(c.ctx, key, username, ttl).Err()
}

func (c *Client) CheckAdminSession(token string) (bool, error) {
	key := "admin_session:" + token

	n, err := c.rdb.Exists(c.ctx, key).Result()
	if err != nil {
		return false, err
	}

	return n > 0, nil
}

func (c *Client) DeleteAdminSession(token string) error {
	return c.rdb.Del(c.ctx, "admin_session:"+token).Err()
}

// ========== 登录失败锁定（防暴力破解）==========

const (
	loginFailPrefix  = "login_fail:"
	loginLockPrefix  = "login_lock:"
	loginMaxAttempts = 3              // 最大允许失败次数
	lockDuration     = 10 * time.Minute // 锁定时长
)

// CheckLoginLock 检查账号是否被锁定
// 返回 (是否锁定, 剩余秒数)
func (c *Client) CheckLoginLock(qq string) (bool, int64) {
	key := loginLockPrefix + qq
	ttl, err := c.rdb.TTL(c.ctx, key).Result()
	if err != nil || ttl <= 0 {
		return false, 0
	}
	return true, int64(ttl.Seconds())
}

// RecordLoginFail 记录一次登录失败
// 返回当前累计失败次数，达到阈值后自动加锁
func (c *Client) RecordLoginFail(qq string) (int, error) {
	failKey := loginFailPrefix + qq

	// INCR 失败计数器（带过期，避免永久占用）
	count, err := c.rdb.Incr(c.ctx, failKey).Result()
	if err != nil {
		return 0, err
	}

	// 首次写入时设置过期（比 lockDuration 稍长一点）
	if count == 1 {
		c.rdb.Expire(c.ctx, failKey, lockDuration+time.Minute)
	}

	// 达到阈值 → 加锁
	if count >= int64(loginMaxAttempts) {
		lockKey := loginLockPrefix + qq
		c.rdb.Set(c.ctx, lockKey, 1, lockDuration)
		c.rdb.Del(c.ctx, failKey) // 清除计数器，解锁后重新计数
	}

	return int(count), nil
}

// ClearLoginFails 登录成功时清除失败计数和锁
func (c *Client) ClearLoginFails(qq string) error {
	keys := []string{loginFailPrefix + qq, loginLockPrefix + qq}
	return c.rdb.Del(c.ctx, keys...).Err()
}
