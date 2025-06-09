package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"regexp"

	_ "github.com/lib/pq"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/config"
)

var DB *sql.DB

// maskPassword, connStr içindeki parolayı gizler.
func maskPassword(connStr string) string {
	re := regexp.MustCompile(`password=([^ ]+)`)
	return re.ReplaceAllString(connStr, "password=***")
}

// InitDB, verilen config.DBConfig’e göre bağlantıyı açar.
func InitDB(cfg config.DBConfig) {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Name,
	)

	slog.Info("DB bağlanılıyor", "conn", maskPassword(connStr))

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		slog.Error("DB sürücüsü açılamadı", "error", err)
		os.Exit(1)
	}

	if err = DB.Ping(); err != nil {
		slog.Error("DB ping başarısız", "error", err)
		os.Exit(1)
	}

	slog.Info("DB bağlantısı başarılı")
}

// CloseDB, açık bağlantıyı kapatır.
func CloseDB() {
	if DB != nil {
		if err := DB.Close(); err != nil {
			slog.Error("DB kapanırken hata", "error", err)
		} else {
			slog.Info("DB bağlantısı kapatıldı")
		}
	}
}
