package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"userControl/config"
	"userControl/func/mail"
	"userControl/func/pgsqlOperate"
	"userControl/func/utils"
	redisOperate "userControl/func/redis"
)

var cfg *config.AppConfig // 包级变量（指针），支持热更新

func main() {
	// 1. 加载配置
	cfg = config.Load()
	mail.CFG = &cfg.Email

	// 2. 初始化 Redis
	redisClient, err := redisOperate.New(cfg.Redis.Addr, cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatalf("[启动失败] 无法连接到 Redis (%s): %v\n请检查 Redis 服务是否运行，以及配置文件中的连接参数是否正确。", cfg.Redis.Addr, err)
	}

	// 3. 初始化 PostgreSQL
	pgEnv := pgsqlOperate.NewPostgresEnv(&cfg.Postgres)
	pool := pgsqlOperate.PostgresSQLInit(*pgEnv)
	defer pool.Close()

	// 4. 实例化 DAO 层
	userDao := &pgsqlOperate.PgDB{Pool: pool}
	InitHandlers(userDao, redisClient) // 注入共享依赖到 handler 层

	// 5. 初始化 AES 加密模块（CDK 加解密）
	utils.InitAES()

	// 6. 启动 HTTP 服务
	gin.SetMode(cfg.Server.Mode)
	r := gin.Default()
	RegisterRoutes(r)

	// 6. 启动定时任务（每日额度重置）
	go startDailyResetTask(userDao)

	// 7. 启动 HTTP 服务（支持优雅关闭）
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.Server.Port),
		Handler: r,
	}

	go func() {
		log.Printf("[服务启动] 监听端口: %s (模式: %s)", cfg.Server.Port, cfg.Server.Mode)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[服务异常] HTTP 服务启动失败: %v", err)
		}
	}()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[服务关闭] 收到信号 %v，正在优雅关闭...", sig)

	// 给在途请求 15 秒完成时间
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[服务关闭] 强制关闭: %v", err)
	}

	log.Println("[服务关闭] 服务已停止")
}
