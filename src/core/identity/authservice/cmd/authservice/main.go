// src/core/identity/authservice/cmd/authservice/main.go
package main

import (
	"context"

	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/app"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/config"
)

func main() {
	// 1) Konfigürasyonu yükle, flag'leri parse et, güncelle ve doğrula
	cfg := config.New()
	config.ParseFlags()
	cfg.UpdateFromParsedFlags()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Config validation error: %v\n", err)
		os.Exit(1)
	}

	// 2) structured Logger'ı kur
	levelVar := new(slog.LevelVar)
	switch strings.ToUpper(cfg.App.LogLevel) {
	case "DEBUG":
		levelVar.Set(slog.LevelDebug)
	case "WARN":
		levelVar.Set(slog.LevelWarn)
	case "ERROR":
		levelVar.Set(slog.LevelError)
	default:
		levelVar.Set(slog.LevelInfo)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: levelVar}))
	slog.SetDefault(logger)

	// 3) App nesnesini oluştur
	application, err := app.New(context.Background(), logger, cfg)
	if err != nil {
		logger.Error("App initialization failed", "error", err)
		os.Exit(1)
	}

	// 4) Uygulamayı çalıştır ve hata varsa çık
	if err := application.Run(context.Background()); err != nil {
		logger.Error("App run error", "error", err)
		os.Exit(1)
	}
}
