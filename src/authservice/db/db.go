package db

import (
	"database/sql"
	"fmt"
	"log/slog" // Değişti
	"os"
	"regexp"

	_ "github.com/lib/pq"
)

var DB *sql.DB

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	slog.Warn("Environment variable not set, using fallback.", "key", key, "fallback", fallback)
	return fallback
}

func maskPassword(connStr string) string {
	re := regexp.MustCompile(`password=([^ ]+)`)
	// Daha güvenli: Şifrenin tamamını göstermeyelim
	return re.ReplaceAllString(connStr, "password=***")
}

func InitDB() {
	dbUser := getEnv("DB_USER", "authuser")
	dbPassword := getEnv("DB_PASSWORD", "authpassword")
	dbName := getEnv("DB_NAME", "authdb")
	dbHost := getEnv("DB_HOST", "postgres-auth-svc")
	dbPort := getEnv("DB_PORT", "5432")

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	slog.Info("Attempting to connect to database...",
		"host", dbHost,
		"port", dbPort,
		"user", dbUser,
		"dbname", dbName,
	)

	var err error
	DB, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		slog.Error("Database driver failed to open connection", "error", err)
		os.Exit(1)
	}

	err = DB.Ping()
	if err != nil {
		slog.Error("Database ping failed after open",
			"error", err,
			"connection_string_masked", maskPassword(psqlInfo),
		)
		os.Exit(1)
	}

	slog.Info("Successfully connected to the database!")
}