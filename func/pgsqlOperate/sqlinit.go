package pgsqlOperate

import (
	"log"
	"time"
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"userControl/config"
)

type PostgresEnv struct {
	cfg *config.PostgresEnv
}

func NewPostgresEnv(cfg *config.PostgresEnv) *PostgresEnv {
	return &PostgresEnv{cfg: cfg}
}

func PostgresSQLInit(env PostgresEnv) *pgxpool.Pool {
	if env.cfg.User == "" || env.cfg.Password == "" || env.cfg.Host == "" || env.cfg.DBName == "" {
		log.Fatal("[PostgresSQLInit] missing required PG env vars")
	}
	if env.cfg.SSLMode == "" {
		env.cfg.SSLMode = "disable"
	}
	dbUrl := "postgres://" + env.cfg.User + ":" + env.cfg.Password + "@" + env.cfg.Host + ":" + env.cfg.Port + "/" + env.cfg.DBName + "?sslmode=" + env.cfg.SSLMode

	config, err := pgxpool.ParseConfig(dbUrl)
	if err != nil {
		log.Fatal("parse config:", err)
	}
	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = 15 * time.Minute
	config.HealthCheckPeriod = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Fatal("connect:", err)
	}

	log.Println("[PostgresSQLInit] PostgreSQL 连接池 & 数据表就绪")

	return pool
}
