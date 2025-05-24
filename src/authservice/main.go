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
	"google.golang.org/grpc/status"

	"github.com/voyalis/voyago-base/src/authservice/db"          // DB paketi
	pb "github.com/voyalis/voyago-base/src/authservice/genproto" // Proto importu
	"github.com/voyalis/voyago-base/src/authservice/repository"  // Repository paketimiz
	"github.com/voyalis/voyago-base/src/authservice/service"     // Servis paketimiz
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

	handlerOptions := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true, // Log mesajına kaynak dosya:satır bilgisini ekler
	}
	// JSONHandler yerine TextHandler da kullanılabilir (geliştirme için daha okunaklı olabilir)
	// handler := slog.NewTextHandler(os.Stdout, handlerOptions) 
	logger := slog.New(slog.NewJSONHandler(os.Stdout, handlerOptions))
	slog.SetDefault(logger)

	slog.Info("Starting VoyaGo AuthService...",
		"service_name", serviceName,
		"port_env_var", portEnvVar,
		"default_port", defaultPort,
		"jwt_secret_env_var", jwtSecretEnv,
		"using_default_jwt_key", isUsingDefaultJWTKey(),
	)

	// 1. Veritabanı bağlantısını başlat
	// db/db.go dosyasındaki InitDB() fonksiyonu db.DB global değişkenini set etmeli.
	db.InitDB() 
	// defer db.DB.Close() // Uzun süreli servislerde main sonunda defer etkili olmaz.

	// 2. Repository ve Service katmanlarını oluştur (Dependency Injection)
	// repository/user_repository.go dosyasındaki NewUserRepo, repository.UserRepoInterface dönmeli.
	userRepo := repository.NewUserRepo(db.DB) 
	
	jwtSecret := getEnv(jwtSecretEnv, defaultJWTKey)
	if jwtSecret == defaultJWTKey { // Bu kontrol zaten isUsingDefaultJWTKey içinde yapılıyor ama burada da log basabiliriz.
		slog.Warn("SECURITY WARNING: Using default JWT_SECRET_KEY. This is INSECURE and for development only. Set a strong JWT_SECRET_KEY environment variable for production.")
	}

	// service/auth_service.go dosyasındaki NewAuthServiceServer, 
	// service.UserRepository (ki bu repository.UserRepoInterface ile aynı olmalı) ve string (secretKey) almalı.
	authSvcServer := service.NewAuthServiceServer(userRepo, jwtSecret)

	// 3. gRPC sunucusunu yapılandır
	port := getEnv(portEnvVar, defaultPort)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		slog.Error("Failed to listen for gRPC server", "port", port, "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor), // Logging interceptor'ını ekliyoruz
	)

	// 4. Servisleri gRPC sunucusuna kaydet
	pb.RegisterAuthServiceServer(grpcServer, authSvcServer) // Proto'dan gelen register fonksiyonu
	registerHealthCheck(grpcServer)                        // Health check servisini kaydet
	reflection.Register(grpcServer)                        // gRPC reflection'ı kaydet

	slog.Info("AuthService is listening", "port", port)
	slog.Info("gRPC server started successfully.")

	// Sunucuyu başlat
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("Failed to serve gRPC server", "error", err)
		os.Exit(1)
	}
}

// registerHealthCheck gRPC health check servisini kaydeder.
func registerHealthCheck(s *grpc.Server) {
	healthSrv := health.NewServer()
	// Başlangıçta genel durumu SERVING yapalım.
	// Daha karmaşık senaryolarda, bağımlılıklar (DB gibi) kontrol edildikten sonra
	// spesifik servisler için durum (örn: "AuthService") ayarlanabilir.
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING) // Tüm servisler için genel durum
	grpc_health_v1.RegisterHealthServer(s, healthSrv)
	slog.Info("Successfully registered gRPC health check service.")
}

// loggingInterceptor her gRPC çağrısı için temel loglama yapar.
func loggingInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	startTime := time.Now()
	// İstek payload'ını loglamak güvenlik riski oluşturabilir, bu yüzden sadece metod adını logluyoruz.
	// Gerekirse DEBUG seviyesinde ve hassas veriler maskelenerek payload loglanabilir.
	slog.InfoContext(ctx, "gRPC Request Started", "method", info.FullMethod)

	resp, err := handler(ctx, req) // Asıl RPC metodunu çağır

	duration := time.Since(startTime)
	if err != nil {
		// gRPC hataları genellikle status.Status tipindedir, buradan daha fazla detay alabiliriz.
		st, _ := status.FromError(err)
		slog.ErrorContext(ctx, "gRPC Request Finished with error",
			"method", info.FullMethod,
			"duration", duration.String(),
			"grpc_code", st.Code().String(), // gRPC hata kodunu logla
			"error", err.Error(),           // Hatanın string mesajı
		)
	} else {
		slog.InfoContext(ctx, "gRPC Request Finished successfully",
			"method", info.FullMethod,
			"duration", duration.String(),
		)
	}
	return resp, err
}