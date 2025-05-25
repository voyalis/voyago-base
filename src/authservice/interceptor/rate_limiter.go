// src/authservice/interceptor/rate_limiter.go
package interceptor

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate" // Bu importun varlığından emin olun
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RateLimiterConfig, rate limiter için yapılandırma ayarlarını tutar.
// (Bir önceki mesajımda IPRateLimiterConfig olarak adlandırmıştım, RateLimiterConfig daha genel olabilir,
// ancak tutarlılık için IPRateLimiterConfig kullanalım veya her yerde aynı ismi kullanalım)
type RateLimiterConfig struct { // "GPT" nin IPRateLimiterConfig yerine bunu kullandığını varsayarak devam ediyorum
	RequestsPerSecond rate.Limit
	Burst             int
	ProtectedMethods  map[string]bool // Hangi RPC metotlarının rate limiting'e tabi olacağı
	CleanupInterval   time.Duration   // Opsiyonel: Eski IP kayıtlarının ne sıklıkla temizleneceği
	// MaxIPAge          time.Duration   // Opsiyonel: Bir IP kaydının ne kadar süre sonra "eski" kabul edileceği
}

type IPRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	config   RateLimiterConfig // BURADA RateLimiterConfig KULLANILIYOR
	// stop     chan struct{} // Cleanup için
}

func NewIPRateLimiter(config RateLimiterConfig) *IPRateLimiter { // BURADA RateLimiterConfig KULLANILIYOR
	limiter := &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
		// stop:   make(chan struct{}), // Cleanup'ı şimdilik basitleştirelim
	}
	// if config.CleanupInterval > 0 && config.MaxIPAge > 0 {
	// 	go limiter.cleanupRoutine()
	// }
	return limiter
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()
	limiter, exists := i.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(i.config.RequestsPerSecond, i.config.Burst)
		i.limiters[ip] = limiter
		slog.Debug("RateLimiter: New limiter created for IP", "ip", ip)
	}
	return limiter
}

// UnaryServerInterceptor ...
func (i *IPRateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if i.config.ProtectedMethods == nil { // Eğer ProtectedMethods tanımlanmamışsa, tüm metotları koru veya hiçbirini koruma
			slog.WarnContext(ctx, "RateLimiter: ProtectedMethods map is nil, rate limiting will not be applied effectively.")
			return handler(ctx, req)
		}

		if _, shouldLimit := i.config.ProtectedMethods[info.FullMethod]; !shouldLimit {
			return handler(ctx, req)
		}

		p, ok := peer.FromContext(ctx)
		if !ok {
			slog.ErrorContext(ctx, "RateLimiter: Could not get peer info", "method", info.FullMethod)
			return nil, status.Errorf(codes.Internal, "could not identify request source")
		}
		ipStr, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			ipStr = p.Addr.String() // Sadece IP olabilir, portsuz
			parsedIP := net.ParseIP(ipStr)
			if parsedIP == nil { // Eğer parse edilemiyorsa, bilinmeyen olarak işaretle
				slog.ErrorContext(ctx, "RateLimiter: Could not parse IP from peer address", "address", p.Addr.String(), "error", err)
				ipStr = "unknown_ip_for_rate_limiting" // Veya hata dön
				// return nil, status.Errorf(codes.Internal, "could not identify request source IP")
			}
		}

		limiter := i.GetLimiter(ipStr)
		if !limiter.Allow() {
			slog.WarnContext(ctx, "RateLimiter: Request rejected", "ip", ipStr, "method", info.FullMethod)
			return nil, status.Errorf(codes.ResourceExhausted, "too many requests from your IP, please try again later")
		}
		return handler(ctx, req)
	}
}