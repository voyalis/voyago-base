package main

import (
	"context"
	"fmt"
	"log/slog" // log/slog import edildi
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/voyalis/voyago-base/src/authservice/genproto" // Proto importu
	"github.com/voyalis/voyago-base/src/authservice/db"         // DB paketi
	"github.com/voyalis/voyago-base/src/authservice/repository" // Repository paketi
	"github.com/voyalis/voyago-base/src/authservice/service"    // Servis paketi
)

const (
	portEnvVar    = "AUTH_SERVICE_PORT"
	defaultPort   = "50051"
	serviceName   = "AuthService" // Health check ve loglar için
	jwtSecretEnv  = "JWT_SECRET_KEY"
	defaultJWTKey = "default_dev_secret_please_change_in_production_for_voyago_auth_123!"
)

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	slog.Warn("Environment variable not set, using fallback value.", "key", key, "fallback", fallback)
	return fallback
}

func isUsingDefaultJWTKey() bool {
	return getEnv(jwtSecretEnv, defaultJWTKey) == defaultJWTKey
}

func main() {
	// Logger yapılandırması
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo) // Varsayılan Info, LOG_LEVEL=DEBUG ile değiştirilebilir

	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		logLevel.Set(slog.LevelDebug)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true, // Kaynak dosya:satır bilgisini ekler
	})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	slog.Info("Starting VoyaGo AuthService...",
		"service_name", serviceName,
		"port_env_var", portEnvVar,
		"default_port", defaultPort,
		"jwt_secret_env_var", jwtSecretEnv,
		"using_default_jwt_key", isUsingDefaultJWTKey(),
	)

	// 1. Veritabanı bağlantısını başlat
	db.InitDB()
	// defer db.DB.Close() // Uzun süreli servislerde etkisi az

	// 2. Repository ve Service katmanlarını oluştur
	userRepo := repository.NewUserRepo(db.DB)
	jwtSecret := getEnv(jwtSecretEnv, defaultJWTKey)
	authSvcServer := service.NewAuthServiceServer(userRepo, jwtSecret)

	// 3. gRPC sunucusunu yapılandır
	port := getEnv(portEnvVar, defaultPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		slog.Error("Failed to listen for gRPC server", "port", port, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor),
	)

	// 4. Servisleri gRPC sunucusuna kaydet
	pb.RegisterAuthServiceServer(grpcServer, authSvcServer)
	registerHealthCheck(grpcServer)
	reflection.Register(grpcServer)

	slog.Info("AuthService is listening", "port", port)
	slog.Info("gRPC server started successfully.")

	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("Failed to serve gRPC server", "error", err)
		os.Exit(1)
	}
}

func registerHealthCheck(s *grpc.Server) {
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, healthSrv)
	slog.Info("Successfully registered gRPC health check service.")
}

func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	startTime := time.Now()
	// slog.DebugContext(ctx, "gRPC Request Started", "method", info.FullMethod, "request_payload", fmt.Sprintf("%+v", req)) // Payload loglamak riskli olabilir
	slog.InfoContext(ctx, "gRPC Request Started", "method", info.FullMethod)

	resp, err := handler(ctx, req)

	duration := time.Since(startTime)
	if err != nil {
		slog.ErrorContext(ctx, "gRPC Request Finished with error",
			"method", info.FullMethod,
			"duration", duration.String(),
			"error", err.Error(), // Hata mesajını string olarak
		)
	} else {
		// slog.DebugContext(ctx, "gRPC Request Finished successfully", "method", info.FullMethod, "duration", duration.String(), "response_payload", fmt.Sprintf("%+v", resp)) // Payload loglamak riskli olabilir
		slog.InfoContext(ctx, "gRPC Request Finished successfully",
			"method", info.FullMethod,
			"duration", duration.String(),
		)
	}
	return resp, err
}