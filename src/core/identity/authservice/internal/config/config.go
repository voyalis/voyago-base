// Package config, uygulama yapılandırmasını merkezi olarak yönetir.
//
// Yapılandırma, aşağıdaki öncelik sırasına göre yüklenir:
//  1. Kod içindeki varsayılan (default) değerler.
//  2. Ortam değişkenleri (Environment Variables).
//  3. Komut satırı argümanları (Command-line Flags).
//
// Ana Kullanım (main.go içinde):
//
//	cfg := config.New()
//	config.ParseFlags()
//	cfg.UpdateFromParsedFlags()
//	if err := cfg.Validate(); err != nil {
//	    log.Fatalf("Konfigürasyon hatası: %v", err)
//	}
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config, uygulama için tüm yapılandırma ayarlarını bir arada tutan ana yapıdır.
type Config struct {
	App       AppConfig
	GRPC      GRPCConfig
	DB        DBConfig
	OTel      OTelConfig
	JWT       JWTConfig
	RateLimit RateLimitConfig
}

type AppConfig struct {
	Name     string
	Version  string
	Env      string
	LogLevel string
}

type GRPCConfig struct {
	Port              string
	MetricsServerPort string
	TLS               TLSConfig
}

type TLSConfig struct {
	CertFile string
	KeyFile  string
}

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type OTelConfig struct {
	Endpoint        string
	ServiceName     string
	ServiceVersion  string
	DeploymentEnv   string
}

type JWTConfig struct {
	Secret string
}

type RateLimitConfig struct {
	MaxRequestsPerMinute int
	Burst                int
	CleanupInterval      time.Duration
}

// Ortam değişkeni adları ve varsayılan değerler
const (
	envAppName        = "OTEL_SERVICE_NAME"
	defaultAppName    = "authservice"
	envAppVersion     = "OTEL_SERVICE_VERSION"
	defaultAppVersion = "0.1.0"
	envAppEnv         = "OTEL_DEPLOYMENT_ENVIRONMENT"
	defaultEnv        = "development"
	envLogLevel       = "LOG_LEVEL"
	defaultLogLevel   = "INFO"

	envGRPCPort        = "PORT"
	defaultGRPCPort    = "50051"
	envMetricsPort     = "METRICS_PORT"
	defaultMetricsPort = "9090"

	envTLSCertFile = "TLS_CERT_FILE"
	envTLSKeyFile  = "TLS_KEY_FILE"

	envDBHost     = "DB_HOST"
	envDBPort     = "DB_PORT"
	envDBUser     = "DB_USER"
	envDBPassword = "DB_PASSWORD"
	envDBName     = "DB_NAME"

	envJWTSecret     = "JWT_SECRET_KEY"
	defaultJWTSecret = "" // Zorunlu kılındı

	envOTelEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"

	envRateMaxPerMin          = "RATE_LIMIT_MAX_PER_MINUTE"
	defaultRateMaxPerMin      = 6000
	envRateBurst              = "RATE_LIMIT_BURST"
	defaultRateBurst          = 200
	envRateCleanup            = "RATE_LIMIT_CLEANUP_MINUTES"
	defaultRateCleanupMinutes = 10
)

var pCleanupMinutes *int

// New, ortam değişkenlerinden okur ve flag'leri tanımlar (flag.Parse() yapmaz).
func New() *Config {
	var cfg Config

	// 1) ENV’den oku
	cfg.App.Name = getEnv(envAppName, defaultAppName)
	cfg.App.Version = getEnv(envAppVersion, defaultAppVersion)
	cfg.App.Env = getEnv(envAppEnv, defaultEnv)
	cfg.App.LogLevel = getEnv(envLogLevel, defaultLogLevel)

	cfg.GRPC.Port = getEnv(envGRPCPort, defaultGRPCPort)
	cfg.GRPC.MetricsServerPort = getEnv(envMetricsPort, defaultMetricsPort)
	cfg.GRPC.TLS.CertFile = getEnv(envTLSCertFile, "")
	cfg.GRPC.TLS.KeyFile = getEnv(envTLSKeyFile, "")

	cfg.DB.Host = getEnv(envDBHost, "postgres-auth-svc")
	cfg.DB.Port = getEnv(envDBPort, "5432")
	cfg.DB.User = getEnv(envDBUser, "")
	cfg.DB.Password = getEnv(envDBPassword, "")
	cfg.DB.Name = getEnv(envDBName, "")

	cfg.JWT.Secret = getEnv(envJWTSecret, defaultJWTSecret)
	cfg.OTel.Endpoint = getEnv(envOTelEndpoint, "")

	cfg.RateLimit.MaxRequestsPerMinute = getEnvInt(envRateMaxPerMin, defaultRateMaxPerMin)
	cfg.RateLimit.Burst = getEnvInt(envRateBurst, defaultRateBurst)
	cleanupMinutes := getEnvInt(envRateCleanup, defaultRateCleanupMinutes)

	// 2) Flag’leri tanımla
	flag.StringVar(&cfg.App.LogLevel, "log-level", cfg.App.LogLevel, "Log level: DEBUG, INFO, WARN, ERROR")
	flag.StringVar(&cfg.GRPC.Port, "grpc-port", cfg.GRPC.Port, "gRPC server port")
	flag.StringVar(&cfg.GRPC.MetricsServerPort, "metrics-port", cfg.GRPC.MetricsServerPort, "Prometheus metrics port")
	flag.StringVar(&cfg.JWT.Secret, "jwt-secret", cfg.JWT.Secret, "JWT secret (ZORUNLU)")
	flag.StringVar(&cfg.DB.Host, "db-host", cfg.DB.Host, "DB host")
	flag.StringVar(&cfg.DB.Port, "db-port", cfg.DB.Port, "DB port")
	flag.StringVar(&cfg.DB.User, "db-user", cfg.DB.User, "DB user")
	flag.StringVar(&cfg.DB.Password, "db-password", cfg.DB.Password, "DB password")
	flag.StringVar(&cfg.DB.Name, "db-name", cfg.DB.Name, "DB name")
	flag.StringVar(&cfg.OTel.Endpoint, "otel-endpoint", cfg.OTel.Endpoint, "OTLP exporter endpoint")
	flag.StringVar(&cfg.GRPC.TLS.CertFile, "tls-cert-file", cfg.GRPC.TLS.CertFile, "TLS cert file")
	flag.StringVar(&cfg.GRPC.TLS.KeyFile, "tls-key-file", cfg.GRPC.TLS.KeyFile, "TLS key file")
	pCleanupMinutes = flag.Int("rate-limit-cleanup-min", cleanupMinutes, "Rate limiter cleanup interval (min)")

	// 3) OTel meta verilerini ayarla
	cfg.OTel.ServiceName = cfg.App.Name
	cfg.OTel.ServiceVersion = cfg.App.Version
	cfg.OTel.DeploymentEnv = cfg.App.Env

	return &cfg
}

// ParseFlags, flag.Parse() çağrısını yapar
func ParseFlags() {
	flag.Parse()
}

// UpdateFromParsedFlags, parse sonrası hesaplama gereken alanları günceller
func (c *Config) UpdateFromParsedFlags() {
	c.RateLimit.CleanupInterval = time.Duration(*pCleanupMinutes) * time.Minute
}

// Validate, Config içindeki kritik değerlerin doğruluğunu kontrol eder
func (c *Config) Validate() error {
	if c.JWT.Secret == "" {
		return errors.New("JWT_SECRET_KEY veya -jwt-secret zorunludur")
	}
	if _, err := strconv.Atoi(c.GRPC.Port); err != nil {
		return fmt.Errorf("geçersiz gRPC port: %s", c.GRPC.Port)
	}
	if _, err := strconv.Atoi(c.GRPC.MetricsServerPort); err != nil {
		return fmt.Errorf("geçersiz metrics port: %s", c.GRPC.MetricsServerPort)
	}
	switch strings.ToUpper(c.App.LogLevel) {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		return fmt.Errorf("geçersiz log seviyesi: %s", c.App.LogLevel)
	}
	if (c.GRPC.TLS.CertFile != "") != (c.GRPC.TLS.KeyFile != "") {
		return errors.New("tls-cert-file ve tls-key-file birlikte set edilmeli")
	}
	// DB ayarları
	if c.DB.Host == "" || c.DB.User == "" || c.DB.Password == "" || c.DB.Name == "" {
		return errors.New("DB_HOST, DB_USER, DB_PASSWORD, DB_NAME zorunludur")
	}
	if _, err := strconv.Atoi(c.DB.Port); err != nil {
		return fmt.Errorf("geçersiz DB port: %s", c.DB.Port)
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if s, ok := os.LookupEnv(key); ok {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return fallback
}
