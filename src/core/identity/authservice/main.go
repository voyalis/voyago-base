// src/core/identity/authservice/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv" // getEnvInt için
	"syscall"
	"time"

	// OpenTelemetry Paketleri
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace" // OTel SDK Trace, InitTraceProvider dönüş tipi için
	"go.opentelemetry.io/otel/trace"              // loggingInterceptorOtel için trace.SpanContextFromContext

	grpcotel "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"

	// Proje Paketleri
	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/db"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/interceptor"
	otelinit "github.com/voyalis/voyago-base/src/core/identity/authservice/otel" // Kendi OTel helper paketimiz
	"github.com/voyalis/voyago-base/src/core/identity/authservice/repository"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/service"

	// gRPC Paketleri
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1" // healthpb olarak alias verdik
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	// Rate limiter için

	// Prometheus + HTTP
	"net/http"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// Servis ve OTel için
	defaultServiceName         = "auth-service"
	defaultServiceVersion      = "0.1.0" // Örnek versiyon
	defaultDeploymentEnv       = "development" // Örnek ortam
	otelServiceNameEnvVar      = "OTEL_SERVICE_NAME"
	otelServiceVersionEnvVar   = "OTEL_SERVICE_VERSION"
	otelDeploymentEnvEnvVar    = "OTEL_DEPLOYMENT_ENVIRONMENT"
	otelExporterEndpointEnvVar  = "OTEL_EXPORTER_OTLP_ENDPOINT"

	// gRPC Portu ve JWT için
	portEnvVarName    = "PORT" // Ortam değişkeni adı
	defaultPort       = "50051"
	jwtSecretEnvVarName = "JWT_SECRET_KEY" // Ortam değişkeni adı
	defaultJWTKey     = "default_dev_secret_please_change_in_production_for_voyago_auth_123!"

	// Rate Limiter için (interceptor.RateLimiterConfig struct'ına göre)
	rateLimitMaxReqPerMinEnvVar = "RATE_LIMIT_MAX_REQ_PER_MINUTE"
	defaultRateLimitMaxReqPerMin = 6000 // Örnek: Dakikada 6000 istek (saniyede 100)
	rateLimitBurstEnvVar        = "RATE_LIMIT_BURST"
	defaultRateLimitBurst       = 200      // Örnek: Anlık 200 istek
	cleanupIntervalEnvVar       = "RATE_LIMIT_CLEANUP_MINUTES"
	defaultCleanupMinutes       = 10
)

// getEnv, bir ortam değişkenini okur, yoksa fallback değerini döner.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	slog.Warn("Ortam değişkeni bulunamadı, varsayılan değer kullanılıyor.", "key", key, "fallback", fallback)
	return fallback
}

// getEnvInt, bir ortam değişkenini integer olarak okur, yoksa fallback değerini döner.
func getEnvInt(key string, fallback int) int {
	if valueStr, exists := os.LookupEnv(key); exists {
		value, err := strconv.Atoi(valueStr)
		if err == nil {
			return value
		}
		slog.Warn("Integer ortam değişkeni parse edilemedi, varsayılan değer kullanılıyor.",
			"key", key, "value_str", valueStr, "fallback", fallback, "error", err.Error())
	}
	return fallback
}

// loggingInterceptorOtel, gelen istekle ilgili bilgileri ve OTel trace/span ID'lerini loglar.
func loggingInterceptorOtel(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	startTime := time.Now()
	spanCtx := trace.SpanContextFromContext(ctx)

	logArgs := []any{
		slog.String("method", info.FullMethod),
	}
	if p, ok := peer.FromContext(ctx); ok {
		logArgs = append(logArgs, slog.String("peer_address", p.Addr.String()))
	}
	if spanCtx.IsValid() {
		logArgs = append(logArgs,
			slog.String("trace_id", spanCtx.TraceID().String()),
			slog.String("span_id", spanCtx.SpanID().String()),
		)
	}

	// JSON Handler kullandığımız için InfoContext veya ErrorContext yerine doğrudan slog.Default().Log kullanabiliriz.
	slog.Default().Log(ctx, slog.LevelInfo, "gRPC Request Started", logArgs...)

	resp, err := handler(ctx, req) // Asıl RPC metodunu çağır

	duration := time.Since(startTime)
	// Mevcut logArgs listesine duration eklemeden önce kopyasını oluşturmak daha güvenli olabilir,
	// ancak burada append ile üzerine yazmak genellikle sorun olmaz.
	// Daha güvenli bir yaklaşım için: currentLogArgs := append([]any(nil), logArgs...)
	currentLogArgs := append(logArgs, slog.String("duration", duration.String()))


	if err != nil {
		st, _ := status.FromError(err)
		errorLogArgs := append(currentLogArgs, slog.String("grpc_code", st.Code().String()), slog.String("error", err.Error()))
		slog.Default().Log(ctx, slog.LevelError, "gRPC Request Finished with error", errorLogArgs...)
	} else {
		slog.Default().Log(ctx, slog.LevelInfo, "gRPC Request Finished successfully", currentLogArgs...)
	}
	return resp, err
}

func main() {
	// Logger ayarı
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo) // Varsayılan Info
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		logLevel.Set(slog.LevelDebug)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel, AddSource: false})) // AddSource: false, çünkü OTel context'i daha iyi bilgi verecek
	slog.SetDefault(logger)

	// Flag / ENV kontrolü
	// Komut satırı flag'leri, ortam değişkenleriyle varsayılan değer alacak şekilde ayarlandı.
	port := flag.String("port", getEnv(portEnvVarName, defaultPort), "gRPC server port (örn: 50051)")
	jwtSecret := flag.String("jwt-secret", getEnv(jwtSecretEnvVarName, defaultJWTKey), "JWT secret key (zorunlu)")
	otelExporterEndpoint := flag.String("otel-exporter-endpoint", getEnv(otelExporterEndpointEnvVar, ""), "OTEL OTLP Exporter Endpoint (örn: otel-collector:4317)")
	otelServiceName := flag.String("otel-service-name", getEnv(otelServiceNameEnvVar, defaultServiceName), "OTEL Service Name")
	otelServiceVersion := flag.String("otel-service-version", getEnv(otelServiceVersionEnvVar, defaultServiceVersion), "OTEL Service Version")
	otelDeploymentEnv := flag.String("otel-deployment-environment", getEnv(otelDeploymentEnvEnvVar, defaultDeploymentEnv), "OTEL Deployment Environment")
	flag.Parse() // Tüm flag'leri parse et

	// OTel Başlatma
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tracerProvider *sdktrace.TracerProvider // sdktrace'i import etmiştik
	if *otelExporterEndpoint != "" {
		var errInitOTel error // Hata değişkenini burada tanımla
		tracerProvider, errInitOTel = otelinit.InitTraceProvider(ctx, *otelServiceName, *otelServiceVersion, *otelDeploymentEnv, *otelExporterEndpoint)
		if errInitOTel != nil {
			slog.Error("OpenTelemetry Trace Provider başlatılamadı, trace'ler gönderilmeyecek.", "error", errInitOTel)
			// Hata durumunda devam edilebilir, ancak trace'ler gönderilmez.
		} else {
			defer func() {
				slog.Info("main.go: defer içinde ShutdownTraceProvider çağrılıyor.")
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer shutdownCancel()
				otelinit.ShutdownTraceProvider(shutdownCtx, tracerProvider)
			}()
		}
	} else {
		slog.Warn("OTEL_EXPORTER_OTLP_ENDPOINT ayarlanmadığı için OpenTelemetry başlatılmadı.")
	}

	slog.Info("VoyaGo AuthService başlatılıyor...",
		"port", *port,
		"otel_service_name", *otelServiceName,
		"otel_service_version", *otelServiceVersion,
		"otel_deployment_environment", *otelDeploymentEnv,
		"otel_exporter_endpoint", *otelExporterEndpoint,
	)
	if *jwtSecret == defaultJWTKey {
		slog.Warn("SECURITY WARNING: Varsayılan JWT_SECRET_KEY kullanılıyor. Bu GÜVENLİ DEĞİLDİR!")
	}

	// Veritabanını başlat
	db.InitDB()
	defer func() {
		if db.DB != nil {
			if err := db.DB.Close(); err != nil {
				slog.Error("Veritabanı bağlantısı kapatılırken hata", "error", err)
			} else {
				slog.Info("Veritabanı bağlantısı başarıyla kapatıldı.")
			}
		}
	}()

	// TCP listener oluştur
	listenAddr := fmt.Sprintf(":%s", *port)
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("TCP Listen hatası", "address", listenAddr, "error", err)
		os.Exit(1)
	}

	// RateLimiter interceptor ayarı
	rlConfig := interceptor.RateLimiterConfig{
		MaxRequestsPerMinute: getEnvInt(rateLimitMaxReqPerMinEnvVar, defaultRateLimitMaxReqPerMin),
		Burst:                getEnvInt(rateLimitBurstEnvVar, defaultRateLimitBurst),
		CleanupInterval:      time.Duration(getEnvInt(cleanupIntervalEnvVar, defaultCleanupMinutes)) * time.Minute,
	}
	ipRateLimiter := interceptor.NewIPRateLimiter(rlConfig)

	// Yeni OpenTelemetry gRPC handler’ı (deprecation yerine)
   handler := grpcotel.NewServerHandler(
       grpcotel.WithTracerProvider(otel.GetTracerProvider()),
       grpcotel.WithPropagators(otel.GetTextMapPropagator()),
   )

	// gRPC Server (Prometheus + OTel(stats handler) + Log + Rate Limiter) interceptors
	grpcServer := grpc.NewServer(
		// 1) OTel yeni API ile gelen stats handler
		grpc.StatsHandler(handler),
		grpc.ChainUnaryInterceptor(
			grpc_prometheus.UnaryServerInterceptor,  // 2. Prometheus metrics interceptor
			loggingInterceptorOtel,                  // 3. JSON log interceptor
			ipRateLimiter.UnaryServerInterceptor(),  // 4. Rate limiter interceptor
    ),

)
	// Repository ve Service ayarları
	userRepo := repository.NewUserRepo(db.DB)
	authSvc := service.NewAuthServiceServer(userRepo, *jwtSecret, rlConfig)
	pb.RegisterAuthServiceServer(grpcServer, authSvc)
	
	// → AuthService için “handled” metriklerini toplamak üzere register et
	grpc_prometheus.EnableHandlingTimeHistogram()
	grpc_prometheus.Register(grpcServer)


	// Healthcheck ve reflection
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus(pb.AuthService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING) // Genel sağlık durumu

	reflection.Register(grpcServer)

	// ---------------------------- BEGIN Prometheus HTTP Endpoint ----------------------------
	go func() {
		// “/metrics” path’ine gelen istekleri promhttp.Handler() ile karşıla
		http.Handle("/metrics", promhttp.Handler())
		// 9090 portunda dinleyecek
		if err := http.ListenAndServe(":9090", nil); err != nil {
			slog.Error("Prometheus metrics endpoint error", "error", err)
		}
	}()
	// ----------------------------- END Prometheus HTTP Endpoint -----------------------------

	// Graceful shutdown ve Serve tek bir blokta
   stopChan := make(chan os.Signal, 1)
   signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

   go func() {
       s := <-stopChan
       slog.Info("Shutdown sinyali alındı.", "signal", s.String())
       grpcServer.GracefulStop()
       cancel()
   }()

   slog.Info("gRPC sunucusu dinlemede.", "address", lis.Addr().String())
   if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
       slog.Error("gRPC Serve hatası", "error", err)
   }
   slog.Info("AuthService uygulaması sonlandırıldı.")
	
}