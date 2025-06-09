// src/core/identity/authservice/internal/app/app.go
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/config"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/db"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/interceptor"
	otelinit "github.com/voyalis/voyago-base/src/core/identity/authservice/internal/otel"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/repository"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/service"
	grpcotel "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// App holds dependencies and servers for the service.
type App struct {
	cfg           *config.Config
	logger        *slog.Logger
	grpcServer    *grpc.Server
	metricsServer *http.Server
	tp            *sdktrace.TracerProvider
}

// New initializes dependencies and returns an App instance.
func New(ctx context.Context, logger *slog.Logger, cfg *config.Config) (*App, error) {
	// 1) Tracing
	var tp *sdktrace.TracerProvider
	if cfg.OTel.Endpoint != "" {
		var err error
		tp, err = otelinit.InitTraceProvider(ctx,
			cfg.OTel.ServiceName,
			cfg.OTel.ServiceVersion,
			cfg.OTel.DeploymentEnv,
			cfg.OTel.Endpoint,
		)
		if err != nil {
			logger.Error("OTel init error, traces disabled", "error", err)
		} else {
			logger.Info("OpenTelemetry started")
		}
	} else {
		logger.Warn("OTEL_EXPORTER_OTLP_ENDPOINT not set, traces disabled")
	}

	// 2) Database
	db.InitDB(cfg.DB)

	// 3) Interceptors
	rc := interceptor.RateLimiterConfig(cfg.RateLimit)
	ipLimiter := interceptor.NewIPRateLimiter(rc)

	// 4) gRPC Server
	grpcServer := grpc.NewServer(
		grpc.StatsHandler(grpcotel.NewServerHandler(grpcotel.WithTracerProvider(otel.GetTracerProvider()))),
		grpc.ChainUnaryInterceptor(
			grpc_prometheus.UnaryServerInterceptor,
			interceptor.Logging,
			ipLimiter.UnaryServerInterceptor(),
		),
	)

	// Register services
	userRepo := repository.NewUserRepo(db.DB)
	authSvc := service.NewAuthServiceServer(userRepo, cfg.JWT.Secret, rc)
	pb.RegisterAuthServiceServer(grpcServer, authSvc)
	grpc_prometheus.EnableHandlingTimeHistogram()
	grpc_prometheus.Register(grpcServer)

	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	healthSrv.SetServingStatus(pb.AuthService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	reflection.Register(grpcServer)

	// 5) Metrics HTTP
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	metricsServer := &http.Server{
		Addr:    ":" + cfg.GRPC.MetricsServerPort,
		Handler: mux,
	}

	logger.Info("Components initialized", "config", cfg)
	return &App{
		cfg:           cfg,
		logger:        logger,
		grpcServer:    grpcServer,
		metricsServer: metricsServer,
		tp:            tp,
	}, nil
}

// Run starts servers and handles graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start metrics
	go func() {
		a.logger.Info("Metrics listening", "addr", a.metricsServer.Addr)
		if err := a.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logger.Error("Metrics error", "error", err)
		}
	}()

	// Start gRPC
	grpcAddr := ":" + a.cfg.GRPC.Port
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("gRPC listen error: %w", err)
	}
	go func() {
		a.logger.Info("gRPC serving", "addr", grpcAddr)
		if err := a.grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			a.logger.Error("gRPC serve error", "error", err)
		}
	}()

	<-ctx.Done()
	a.logger.Info("Shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Shutdown sequence
	if err := a.metricsServer.Shutdown(shutdownCtx); err != nil {
		a.logger.Error("Metrics shutdown error", "error", err)
	} else {
		a.logger.Info("Metrics stopped")
	}
	a.grpcServer.GracefulStop()
	a.logger.Info("gRPC stopped")
	db.CloseDB()
	a.logger.Info("DB closed")
	if a.tp != nil {
		a.logger.Info("Shutting down tracer provider")
		if err := a.tp.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("TracerProvider shutdown err", "error", err)
		} else {
			a.logger.Info("TracerProvider stopped")
		}
	}
	a.logger.Info("Application terminated gracefully")
	return nil
}
