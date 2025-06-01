package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv" // getEnvInt için eklendi
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status" 

	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
	"github.com/voyalis/voyago-base/src/core.identity/authservice/db"
	"github.com/voyalis/voyago-base/src/core.identity/authservice/interceptor" // YENİ: Rate Limiter interceptor'ı için
	"github.com/voyalis/voyago-base/src/core.identity/authservice/repository"
	"github.com/voyalis/voyago-base/src/core.identity/authservice/service"
	"golang.org/x/time/rate" 
)

const (
	portEnvVar            = "AUTH_SERVICE_PORT"
	defaultPort           = "50051"
	serviceName           = "AuthService"
	jwtSecretEnv          = "JWT_SECRET_KEY"
	defaultJWTKey         = "default_dev_secret_please_change_in_production_for_voyago_auth_123!"
	rateLimitRPSEnv       = "RATE_LIMIT_RPS"       // Saniyede istek limiti için ortam değişkeni
	defaultRateLimitRPS   = 5                      // Varsayılan saniyede istek limiti
	rateLimitBurstEnv     = "RATE_LIMIT_BURST"     // Anlık patlama kapasitesi için ortam değişkeni
	defaultRateLimitBurst = 10                     // Varsayılan anlık patlama kapasitesi
	cleanupIntervalEnv    = "RATE_LIMIT_CLEANUP_MINUTES" // Temizleme aralığı için ortam değişkeni
	defaultCleanupMinutes = 10                         // Varsayılan temizleme aralığı (dakika)
)

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	slog.Warn("Environment variable not set, using fallback value.", "key", key, "fallback", fallback)
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if valueStr, exists := os.LookupEnv(key); exists {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
		slog.Warn("Failed to parse integer environment variable, using fallback.", "key", key, "value_str", valueStr, "fallback", fallback)
	}
	return fallback
}

func isUsingDefaultJWTKey() bool {
	return getEnv(jwtSecretEnv, defaultJWTKey) == defaultJWTKey
}

func main() {
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		logLevel.Set(slog.LevelDebug)
	}
	handlerOptions := &slog.HandlerOptions{Level: logLevel, AddSource: true}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, handlerOptions))
	slog.SetDefault(logger)

	slog.Info("Starting VoyaGo AuthService...",
		"service_name", serviceName,
		"port_env_var", portEnvVar,
		"default_port", defaultPort,
		"jwt_secret_env_var", jwtSecretEnv,
		"using_default_jwt_key", isUsingDefaultJWTKey(),
	)

	db.InitDB()
	userRepo := repository.NewUserRepo(db.DB)
	jwtSecret := getEnv(jwtSecretEnv, defaultJWTKey)
	if jwtSecret == defaultJWTKey {
		slog.Warn("SECURITY WARNING: Using default JWT_SECRET_KEY. This is INSECURE and for development only. Set a strong JWT_SECRET_KEY environment variable for production.")
	}

	// Rate Limiter Yapılandırması
	rlConfig := interceptor.RateLimiterConfig{
		RequestsPerSecond: rate.Limit(getEnvInt(rateLimitRPSEnv, defaultRateLimitRPS)),
		Burst:             getEnvInt(rateLimitBurstEnv, defaultRateLimitBurst),
		CleanupInterval:   time.Duration(getEnvInt(cleanupIntervalEnv, defaultCleanupMinutes)) * time.Minute,
		ProtectedMethods: map[string]bool{
			"/authservice.AuthService/Login":                true,
			"/authservice.AuthService/RequestPasswordReset": true,
			// İsteğe bağlı olarak diğer metotlar eklenebilir:
			// "/authservice.AuthService/Register": true,
			// "/authservice.AuthService/RequestEmailVerification": true,
		},
	}
	// NewAuthServiceServer'a rlConfig parametresini iletiyoruz
	authSvcServer := service.NewAuthServiceServer(userRepo, jwtSecret, rlConfig)

	port := getEnv(portEnvVar, defaultPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		slog.Error("Failed to listen for gRPC server", "port", port, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor( // Birden fazla interceptor için ChainUnaryInterceptor
			loggingInterceptor,                     // Mevcut logging interceptor'ımız
			authSvcServer.RateLimitInterceptor(), // YENİ: Rate limiting interceptor
		),
	)

	pb.RegisterAuthServiceServer(grpcServer, authSvcServer)
	registerHealthCheck(grpcServer)
	reflection.Register(grpcServer)

	slog.Info("AuthService is listening with Rate Limiting enabled", "port", port,
		"rate_limit_rps", rlConfig.RequestsPerSecond,
		"burst", rlConfig.Burst,
		"protected_methods_count", len(rlConfig.ProtectedMethods),
	)
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
	slog.InfoContext(ctx, "gRPC Request Started", "method", info.FullMethod)

	resp, err := handler(ctx, req)

	duration := time.Since(startTime)
	logFields := []interface{}{
		"method", info.FullMethod,
		"duration", duration.String(),
	}

	if err != nil {
		st, _ := status.FromError(err)
		logFields = append(logFields, "grpc_code", st.Code().String(), "error", err.Error())
		slog.ErrorContext(ctx, "gRPC Request Finished with error", logFields...)
	} else {
		slog.InfoContext(ctx, "gRPC Request Finished successfully", logFields...)
	}
	return resp, err
}