// Package main is the entrypoint for the AuthService.
// It loads configuration, initializes dependencies, and
// manages the application lifecycle (startup & graceful shutdown).
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"log/slog"

	// Prometheus & OpenTelemetry
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	grpcotel "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	// Project packages
	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/db"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/interceptor"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/internal/config"
	otelinit "github.com/voyalis/voyago-base/src/core/identity/authservice/otel"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/repository"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/service"

	// gRPC
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

// loggingInterceptorOtel logs each gRPC request along with OTel trace/span IDs.
// We'll move this into interceptor/ in Faz 2.
func loggingInterceptorOtel(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()
	spanCtx := trace.SpanContextFromContext(ctx)

	args := []any{slog.String("method", info.FullMethod)}
	if p, ok := peer.FromContext(ctx); ok {
		args = append(args, slog.String("peer", p.Addr.String()))
	}
	if spanCtx.IsValid() {
		args = append(args,
			slog.String("trace_id", spanCtx.TraceID().String()),
			slog.String("span_id", spanCtx.SpanID().String()),
		)
	}
	slog.Default().Log(ctx, slog.LevelInfo, "gRPC request start", args...)

	resp, err := handler(ctx, req)

	duration := time.Since(start)
	args = append(args, slog.String("duration", duration.String()))

	if err != nil {
		st, _ := status.FromError(err)
		slog.Default().Log(ctx, slog.LevelError, "gRPC request failed",
			append(args,
				slog.String("grpc_code", st.Code().String()),
				slog.String("error", err.Error()),
			)...,
		)
	} else {
		slog.Default().Log(ctx, slog.LevelInfo, "gRPC request ok", args...)
	}
	return resp, err
}

func main() {
	// 1) Load & parse config
	cfg := config.New()
	config.ParseFlags()
	cfg.UpdateFromParsedFlags()
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	// 2) Set up structured logger
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

	// 3) Initialize OpenTelemetry
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tp *sdktrace.TracerProvider
	if cfg.OTel.Endpoint != "" {
		var err error
		tp, err = otelinit.InitTraceProvider(
			ctx,
			cfg.OTel.ServiceName,
			cfg.OTel.ServiceVersion,
			cfg.OTel.DeploymentEnv,
			cfg.OTel.Endpoint,
		)
		if err != nil {
			slog.Error("OTel init failed, traces disabled", "err", err)
		} else {
			defer func() {
				slog.Info("Shutting down OTel TracerProvider")
				shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shCancel()
				otelinit.ShutdownTraceProvider(shCtx, tp)
			}()
		}
	} else {
		slog.Warn("OTEL_EXPORTER_OTLP_ENDPOINT not set, no tracing")
	}

	slog.Info("Starting AuthService", "config", cfg)

	// 4) Connect to database
	db.InitDB(cfg.DB)
	defer db.CloseDB()

	// 5) Start listening on gRPC port
	addr := fmt.Sprintf(":%s", cfg.GRPC.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("TCP listen failed", "addr", addr, "err", err)
		os.Exit(1)
	}

	// 6) Build gRPC server with interceptors
	// Convert our config.RateLimitConfig → interceptor.RateLimiterConfig
	rlCfg := interceptor.RateLimiterConfig{
		MaxRequestsPerMinute: cfg.RateLimit.MaxRequestsPerMinute,
		Burst:                cfg.RateLimit.Burst,
		CleanupInterval:      cfg.RateLimit.CleanupInterval,
	}
	ipRL := interceptor.NewIPRateLimiter(rlCfg)

	grpcServer := grpc.NewServer(
		grpc.StatsHandler(grpcotel.NewServerHandler()), // OTel stats
		grpc.ChainUnaryInterceptor(
			grpc_prometheus.UnaryServerInterceptor, // Prometheus
			loggingInterceptorOtel,                 // Logging + OTel IDs
			ipRL.UnaryServerInterceptor(),          // Rate limiting
		),
	)

	// 7) Register our AuthService
	userRepo := repository.NewUserRepo(db.DB)
	authSvc := service.NewAuthServiceServer(userRepo, cfg.JWT.Secret, rlCfg)
	pb.RegisterAuthServiceServer(grpcServer, authSvc)
	grpc_prometheus.EnableHandlingTimeHistogram()
	grpc_prometheus.Register(grpcServer)

	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthSrv)
	healthSrv.SetServingStatus(pb.AuthService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	reflection.Register(grpcServer)

	// 8) Launch Prometheus HTTP endpoint
	go func() {
		metricsAddr := fmt.Sprintf(":%s", cfg.GRPC.MetricsServerPort)
		slog.Info("Metrics HTTP endpoint listening", "addr", metricsAddr)
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			slog.Error("Metrics HTTP server failed", "err", err)
		}
	}()

	// 9) Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("gRPC server serving", "addr", addr)
		if err := grpcServer.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			slog.Error("gRPC Serve error", "err", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Shutdown signal received, stopping gRPC server")
	grpcServer.GracefulStop()
	slog.Info("AuthService stopped")
}
