// 4️⃣ interceptor/logging.go
package interceptor

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Logging, gRPC isteklerini loglar ve OTel span bilgisi ekler
func Logging(
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
