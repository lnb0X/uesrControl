package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"userControl/func/pgsqlOperate"
)

// ping 健康检查端点
func ping(c *gin.Context) {
	c.JSON(200, gin.H{"msg": "pong"})
}

// startDailyResetTask 每日凌晨 0 点重置所有用户的每日免费额度
// 将 daily_limit 重置为 max_daily_limit，每个用户按各自的上限独立重置
// 如果执行失败，每隔 5 分钟重试，直到成功为止
func startDailyResetTask(userDao *pgsqlOperate.PgDB) {
	for {
		now := time.Now()
		next := now.Add(time.Hour * 24)
		next = time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, next.Location())

		t := time.NewTimer(next.Sub(now))
		fmt.Printf("[系统任务] 额度重置计划已就绪，下次执行：%v\n", next.Format("2006-01-02 15:04:05"))

		<-t.C

		// 执行重置，失败则每 5 分钟重试，最多 12 次（1 小时）
		const maxRetries = 12
		for attempt := 1; ; attempt++ {
			_, err := userDao.Pool.Exec(context.Background(),
				"UPDATE user_api_assets SET daily_limit = max_daily_limit WHERE has_permission = TRUE")

			if err != nil {
				if attempt >= maxRetries {
					fmt.Printf("[系统任务][严重] 自动重置连续失败 %d 次，放弃本次重置: %v\n", attempt, err)
					break
				}
				fmt.Printf("[系统任务] 自动重置失败(%d/%d): %v，5 分钟后重试...\n", attempt, maxRetries, err)
				time.Sleep(5 * time.Minute)
				continue
			}

			fmt.Println("[系统任务] 每日免费额度已根据用户各自上限完成重置")
			break
		}
	}
}
