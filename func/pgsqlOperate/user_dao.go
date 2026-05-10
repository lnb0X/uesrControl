package pgsqlOperate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"userControl/func/utils"
)

func GenerateRandomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (db *PgDB) GetUserByToken(token string) (qq string, err error) {
	err = db.Pool.QueryRow(context.Background(),
		"SELECT qq FROM users WHERE api_token = $1 AND status = 1",
		token).Scan(&qq)
	return
}

func (db *PgDB) RegisterUser(qq, password string) (string, error) {
	ctx := context.Background()

	token := GenerateRandomToken()
	if token == "" {
		return "", fmt.Errorf("token 生成失败")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码加密失败: %v", err)
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		"INSERT INTO users (qq, password_hash, api_token) VALUES ($1, $2, $3)",
		qq, string(hashedPassword), token)
	if err != nil {
		return "", fmt.Errorf("用户表写入失败: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return token, nil
}

func (db *PgDB) CheckApiPermission(qq, apiName string) (bool, error) {
	var hasPermission bool
	err := db.Pool.QueryRow(context.Background(),
		"SELECT has_permission FROM user_api_assets WHERE qq = $1 AND api_name = $2",
		qq, apiName).Scan(&hasPermission)

	if err == pgx.ErrNoRows {
		return false, nil
	}
	return hasPermission, err
}

func (db *PgDB) GetUserAssets(qq, apiName string) (dailyLimit, extraBalance int, err error) {
	err = db.Pool.QueryRow(context.Background(),
		"SELECT daily_limit, extra_balance FROM user_api_assets WHERE qq = $1 AND api_name = $2",
		qq, apiName).Scan(&dailyLimit, &extraBalance)
	return
}

func (db *PgDB) UseCDKCard(qq string, encryptedKey string) (string, error) {
	ctx := context.Background()

	payload, err := utils.DecryptCDK(encryptedKey)
	if err != nil {
		return "无效的卡密格式", err
	}

	if time.Now().Unix() > payload.ExpiresAt {
		return "该卡密已过期", errors.New("cdk expired")
	}

	if payload.ScopeType == 1 && payload.ScopeValue != qq {
		return "此卡密为指定用户专属，您无法使用", errors.New("scope mismatch: qq")
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "服务器繁忙，请稍后再试", err
	}
	defer tx.Rollback(ctx)

	var dbApiName string
	var dbCardType int16
	var dbFaceValue int
	var dbMaxUses int
	err = tx.QueryRow(ctx,
		"SELECT api_name, card_type, face_value, max_uses FROM cdk_cards WHERE card_key = $1",
		encryptedKey).Scan(&dbApiName, &dbCardType, &dbFaceValue, &dbMaxUses)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "卡密不存在或已被废弃", err
		}
		return "数据库查询失败", err
	}

	// 检查使用次数是否已达上限（max_uses=0 表示不限次数）
	if dbMaxUses > 0 {
		var usedCount int
		err = tx.QueryRow(ctx,
			"SELECT COUNT(*) FROM user_cdk_usage WHERE card_key = $1", encryptedKey).Scan(&usedCount)
		if err != nil {
			return "查询卡密使用次数失败", err
		}
		if usedCount >= dbMaxUses {
			return "该卡密使用次数已达上限", errors.New("cdk usage limit reached")
		}
	}

	if payload.ScopeType == 2 {
		var userStatus int16
		err = tx.QueryRow(ctx, "SELECT status FROM users WHERE qq = $1", qq).Scan(&userStatus)
		if err != nil {
			return "查询用户身份失败", err
		}

		if fmt.Sprintf("%d", userStatus) != payload.ScopeValue {
			return "您的账号等级不符合该卡密的使用条件", errors.New("status mismatch")
		}
	}

	_, err = tx.Exec(ctx, "INSERT INTO user_cdk_usage (qq, card_key) VALUES ($1, $2)", qq, encryptedKey)
	if err != nil {
		return "您已经兑换过该卡密，请勿重复操作", err
	}

	var updateSql string
	switch dbCardType {
	case 1:
		updateSql = "UPDATE user_api_assets SET extra_balance = extra_balance + $1 WHERE qq = $2 AND api_name = $3"
	case 2:
		updateSql = `UPDATE user_api_assets 
                     SET daily_limit = daily_limit + $1, 
                         max_daily_limit = max_daily_limit + $1 
                     WHERE qq = $2 AND api_name = $3`
	case 3:
		updateSql = "UPDATE user_api_assets SET has_permission = TRUE WHERE qq = $1 AND api_name = $2"
	default:
		return "未知的卡片类型", errors.New("unknown card type")
	}

	var tag pgconn.CommandTag
	if dbCardType == 3 {
		tag, err = tx.Exec(ctx, updateSql, qq, dbApiName)
	} else {
		tag, err = tx.Exec(ctx, updateSql, dbFaceValue, qq, dbApiName)
	}

	if err != nil {
		return "资产更新失败", err
	}
	if tag.RowsAffected() == 0 {
		// 【修复点1】: 如果是加每日额度(cardType=2)，需要把 max_daily_limit 也写进去
		var initDaily, initMax, initExtra int
		if dbCardType == 1 {
			initExtra = dbFaceValue
		} else if dbCardType == 2 {
			initDaily = dbFaceValue
			initMax = dbFaceValue
		}

		_, err = tx.Exec(ctx,
			`INSERT INTO user_api_assets 
			(qq, api_name, has_permission, daily_limit, max_daily_limit, extra_balance) 
			VALUES ($1, $2, $3, $4, $5, $6)`,
			qq, dbApiName, true, initDaily, initMax, initExtra)
			
		if err != nil {
			return "初始化资产失败", err
		}
	}

	statSql := `UPDATE users SET 
				used_card_count = used_card_count + 1,
				total_added_daily_limit = total_added_daily_limit + $1,
				total_added_extra_balance = total_added_extra_balance + $2
				WHERE qq = $3`

	var addDaily, addExtra int
	if dbCardType == 2 {
		addDaily = dbFaceValue
	}
	if dbCardType == 1 {
		addExtra = dbFaceValue
	}

	tx.Exec(ctx, statSql, addDaily, addExtra, qq)

	if err := tx.Commit(ctx); err != nil {
		return "兑换提交失败", err
	}

	return "兑换成功！资产已更新", nil
}

func (db *PgDB) CreateCDK(cardKey string, scopeType int16, scopeValue string, cardType int16, apiName string, faceValue int, expiresAt time.Time, maxUses int) error {
	ctx := context.Background()
	query := `INSERT INTO cdk_cards 
		(card_key, scope_type, scope_value, card_type, api_name, face_value, expires_at, max_uses) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := db.Pool.Exec(ctx, query, cardKey, scopeType, scopeValue, cardType, apiName, faceValue, expiresAt, maxUses)
	return err
}

type UserFilter struct {
	QQ      string // 精确搜索 QQ 号
	Status  string // 账号状态筛选，空=全部
	MinCards int   // 最小用卡数
	MaxCards int   // 最大用卡数
	HasApi   string // 接口权限筛选："yes"=有权限, "no"=无任何权限, ""=全部
	ApiName  string // 具体接口名称筛选，空=全部（如 "gpt-4o", "claude-3.5" 等）
}

func (db *PgDB) GetAllUsers(limit, offset int, f UserFilter) ([]map[string]interface{}, int, error) {
	ctx := context.Background()

	// 构建动态 WHERE 条件
	var conditions []string
	var args []interface{}
	argIdx := 1

	if f.QQ != "" {
		conditions = append(conditions, fmt.Sprintf("u.qq = $%d", argIdx))
		args = append(args, f.QQ)
		argIdx++
	}
	if f.Status != "" {
		conditions = append(conditions, fmt.Sprintf("u.status = $%d", argIdx))
		args = append(args, f.Status)
		argIdx++
	}
	if f.MinCards > 0 {
		conditions = append(conditions, fmt.Sprintf("u.used_card_count >= $%d", argIdx))
		args = append(args, f.MinCards)
		argIdx++
	}
	if f.MaxCards > 0 {
		conditions = append(conditions, fmt.Sprintf("u.used_card_count <= $%d", argIdx))
		args = append(args, f.MaxCards)
		argIdx++
	}
	if f.HasApi == "yes" {
		// 有接口权限：EXISTS 至少一条 has_permission=TRUE 的资产记录
		conditions = append(conditions, "EXISTS(SELECT 1 FROM user_api_assets a2 WHERE a2.qq = u.qq AND a2.has_permission = TRUE)")
	} else if f.HasApi == "no" {
		// 无任何接口权限：NOT EXISTS 或所有权限都是 FALSE
		conditions = append(conditions, "NOT EXISTS(SELECT 1 FROM user_api_assets a2 WHERE a2.qq = u.qq AND a2.has_permission = TRUE)")
	}
	if f.ApiName != "" {
		// 按具体接口名称筛选（精确匹配）
		conditions = append(conditions, fmt.Sprintf("EXISTS(SELECT 1 FROM user_api_assets a3 WHERE a3.qq = u.qq AND a3.api_name = $%d)", argIdx))
		args = append(args, f.ApiName)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// 查询总数（带相同条件）
	countSQL := "SELECT COUNT(*) FROM users u " + whereClause
	var total int
	err := db.Pool.QueryRow(ctx, countSQL, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query := `
		SELECT 
			u.id, u.qq, u.status, u.used_card_count, u.created_at,
			COALESCE(json_agg(json_build_object(
				'api_name', a.api_name,
				'daily_limit', a.daily_limit,
				'max_daily_limit', a.max_daily_limit,
				'extra_balance', a.extra_balance,
				'has_permission', a.has_permission
			)) FILTER (WHERE a.api_name IS NOT NULL), '[]') as assets
		FROM users u
		LEFT JOIN user_api_assets a ON u.qq = a.qq ` + whereClause + `
		GROUP BY u.id
		ORDER BY u.id DESC 
		LIMIT $` + fmt.Sprintf("%d", argIdx) + ` OFFSET $` + fmt.Sprintf("%d", argIdx+1)

	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int64
		var qq, statusStr string
		var count int
		var createdAt time.Time
		var assets interface{}

		err := rows.Scan(&id, &qq, &statusStr, &count, &createdAt, &assets)
		if err != nil {
			fmt.Println("Scan用户列表失败:", err)
			continue
		}

		users = append(users, map[string]interface{}{
			"id": id, "qq": qq, "status": statusStr,
			"used_cards": count, "created_at": createdAt,
			"assets": assets,
		})
	}
	return users, total, nil
}

func (db *PgDB) GetAllCDKs(limit, offset int) ([]map[string]interface{}, int, error) {
	ctx := context.Background()

	var total int
	err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM cdk_cards").Scan(&total)
	if err != nil {
		fmt.Println("统计卡密总数失败:", err)
		return nil, 0, err
	}

	query := `SELECT c.card_key, c.scope_type, c.scope_value, c.card_type, c.api_name, 
	                  c.face_value, c.expires_at, c.created_at, c.max_uses,
	                  COALESCE(u.used_count, 0) as used_count
	          FROM cdk_cards c
	          LEFT JOIN (SELECT card_key, COUNT(*) as used_count FROM user_cdk_usage GROUP BY card_key) u
	                  ON c.card_key = u.card_key
	          ORDER BY c.created_at DESC LIMIT $1 OFFSET $2`
	rows, err := db.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		fmt.Println("查询卡密列表失败:", err)
		return nil, 0, err
	}
	defer rows.Close()

	cdks := make([]map[string]interface{}, 0)
	for rows.Next() {
		var cardKey, apiName string
		var scopeValue *string
		var createdAt *time.Time
		var scopeType, cardType int16
		var faceValue, maxUses, usedCount int
		var expiresAt time.Time

		err := rows.Scan(
			&cardKey, &scopeType, &scopeValue,
			&cardType, &apiName, &faceValue, &expiresAt, &createdAt,
			&maxUses, &usedCount,
		)

		if err != nil {
			fmt.Println("Scan 卡密数据失败:", err)
			continue
		}

		sv := ""
		if scopeValue != nil {
			sv = *scopeValue
		}
		ca := time.Now()
		if createdAt != nil {
			ca = *createdAt
		}

		cdks = append(cdks, map[string]interface{}{
			"card_key":    cardKey,
			"scope_type":  scopeType,
			"scope_value": sv,
			"card_type":   cardType,
			"api_name":    apiName,
			"face_value":  faceValue,
			"expires_at":  expiresAt,
			"created_at":  ca,
			"max_uses":    maxUses,
			"used_count":  usedCount,
		})
	}
	return cdks, total, nil
}

func (db *PgDB) UpdateUserStatus(qq string, status int16) error {
	_, err := db.Pool.Exec(context.Background(), "UPDATE users SET status = $1 WHERE qq = $2", status, qq)
	return err
}

func (db *PgDB) UpdateUserApiLimit(qq, apiName string, dailyLimit int, hasPerm bool) error {
	_, err := db.Pool.Exec(context.Background(),
		`UPDATE user_api_assets 
         SET daily_limit = $1, 
             max_daily_limit = $1,  -- 【新增】同步修改上限，确保明天重置后依然是这个数
             has_permission = $2 
         WHERE qq = $3 AND api_name = $4`,
		dailyLimit, hasPerm, qq, apiName)
	return err
}

func (db *PgDB) RevokeCDK(cardKey string) error {
	_, err := db.Pool.Exec(context.Background(), "DELETE FROM cdk_cards WHERE card_key = $1", cardKey)
	return err
}

func (db *PgDB) UpdateUserPassword(qq, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Pool.Exec(context.Background(),
		"UPDATE users SET password_hash = $1 WHERE qq = $2",
		string(hashedPassword), qq)
	return err
}

// RegenUserApiToken 为指定用户重新生成 api_token，返回新 token
func (db *PgDB) RegenUserApiToken(qq string) (string, error) {
	newToken := GenerateRandomToken()
	if newToken == "" {
		return "", fmt.Errorf("token 生成失败")
	}
	_, err := db.Pool.Exec(context.Background(),
		"UPDATE users SET api_token = $1 WHERE qq = $2", newToken, qq)
	if err != nil {
		return "", err
	}
	return newToken, nil
}

func (db *PgDB) DeleteUserApiAsset(qq, apiName string) error {
	_, err := db.Pool.Exec(context.Background(),
		"DELETE FROM user_api_assets WHERE qq = $1 AND api_name = $2",
		qq, apiName)
	return err
}

func (db *PgDB) DeleteUser(qq string) error {
	ctx := context.Background()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tx.Exec(ctx, "DELETE FROM user_cdk_usage WHERE qq = $1", qq)
	tx.Exec(ctx, "DELETE FROM user_api_assets WHERE qq = $1", qq)
	_, err = tx.Exec(ctx, "DELETE FROM users WHERE qq = $1", qq)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// 返回值改为了：data数据, 状态码, 错误信息
func (db *PgDB) GetUserQuotaDetail(token string, apiName string) (map[string]interface{}, int, error) {
	ctx := context.Background()
	var qq string
	var status int16

	// 第一步：只验证 Token 是否存在
	err := db.Pool.QueryRow(ctx, "SELECT qq, status FROM users WHERE api_token = $1", token).Scan(&qq, &status)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, 401, errors.New("无效的 Token，用户不存在")
		}
		return nil, 500, errors.New("数据库查询失败")
	}

	// 第二步：查询对应接口的资产
	var dailyLimit, extraBalance int
	var hasPermission bool
	err = db.Pool.QueryRow(ctx, `
		SELECT daily_limit, extra_balance, has_permission 
		FROM user_api_assets 
		WHERE qq = $1 AND api_name = $2`, 
		qq, apiName).Scan(&dailyLimit, &extraBalance, &hasPermission)

	if err != nil {
		if err == pgx.ErrNoRows {
			// Token 存在，但没有此 API 的资产
			return nil, 404, errors.New("当前用户未获取该 API 的资产")
		}
		return nil, 500, errors.New("资产查询失败")
	}

	return map[string]interface{}{
		"status":         status,
		"daily_limit":    dailyLimit,
		"extra_balance":  extraBalance,
		"has_permission": hasPermission,
	}, 200, nil
}

func (db *PgDB) DeductApiQuotaSecure(token string, apiName string, cost int, allowExtra bool) (bool, error) {
	ctx := context.Background()

	var qq string
	var userStatus int16
	err := db.Pool.QueryRow(ctx, "SELECT qq, status FROM users WHERE api_token = $1", token).Scan(&qq, &userStatus)
	if err != nil {
		return false, errors.New("无效的 Token 或用户不存在")
	}
	if userStatus == 0 {
		return false, errors.New("账号已被封禁，无法调用")
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var dailyLimit, extraBalance int
	var hasPermission bool
	err = tx.QueryRow(ctx, `
		SELECT daily_limit, extra_balance, has_permission 
		FROM user_api_assets 
		WHERE qq = $1 AND api_name = $2 
		FOR UPDATE`, qq, apiName).Scan(&dailyLimit, &extraBalance, &hasPermission)

	if err != nil {
		return false, errors.New("未查询到该 API 的资产记录")
	}
	if !hasPermission {
		return false, errors.New("该接口权限已被管理员关闭")
	}

	if dailyLimit >= cost {
		_, err = tx.Exec(ctx, "UPDATE user_api_assets SET daily_limit = daily_limit - $1 WHERE qq = $2 AND api_name = $3", cost, qq, apiName)
	} else {
		if !allowExtra {
			return false, errors.New("免费额度不足，需要用户授权扣除付费余额")
		}

		if (dailyLimit + extraBalance) < cost {
			return false, errors.New("总余额不足，请先充值")
		}

		remainingCost := cost - dailyLimit
		_, err = tx.Exec(ctx, `
			UPDATE user_api_assets 
			SET daily_limit = 0, extra_balance = extra_balance - $1 
			WHERE qq = $2 AND api_name = $3`, remainingCost, qq, apiName)
	}

	if err != nil {
		return false, fmt.Errorf("数据库更新失败: %v", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		return false, err
	}

	return true, nil
}
