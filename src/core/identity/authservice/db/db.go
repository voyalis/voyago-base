package db

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"regexp"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	slog.Warn("ENV yok, fallback kullanılıyor", "key", key, "fallback", fallback)
	return fallback
}

func maskPassword(connStr string) string {
	re := regexp.MustCompile(`password=([^ ]+)`)
	return re.ReplaceAllString(connStr, "password=***")
}

func InitDB() {
	dbUser := getEnv("DB_USER", "authuser")
	dbPassword := getEnv("DB_PASSWORD", "authpassword")
	dbName := getEnv("DB_NAME", "authdb")
	dbHost := getEnv("DB_HOST", "postgres-auth-svc")
	dbPort := getEnv("DB_PORT", "5432")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	slog.Info("Veritabanına bağlanılıyor...", "host", dbHost, "port", dbPort, "user", dbUser, "dbName", dbName)

	var err error
	DB, err = sql.Open("postgres", connStr)
	if err != nil {
		slog.Error("DB sürücüsü açılamadı", "error", err)
		os.Exit(1)
	}

	if err = DB.Ping(); err != nil {
		slog.Error("DB ping başarısız", "error", err, "connStr", maskPassword(connStr))
		os.Exit(1)
	}

	slog.Info("Veritabanına başarıyla bağlanıldı!")
}
