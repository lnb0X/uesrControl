package pgsqlOperate

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgDB struct {
	Pool *pgxpool.Pool
}
