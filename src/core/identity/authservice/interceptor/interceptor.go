// src/core/identity/authservice/interceptor/interceptor.go
package interceptor

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RateLimiterConfig, burada kullandığınız alan isimlerine bire bir uymalıdır.
// Eğer kendi kodunuzda farklı isimler varsa onları buraya geçirin.
type RateLimiterConfig struct {
	// Örnek alanlar:
	MaxRequestsPerMinute int           // Saniyeye değil dakikaya göre sınır
	Burst                int           // Kısa süreli patlamalar için izin
	CleanupInterval      time.Duration // Boş IP kayıtlarını temizleme periyodu
	// Eğer ProtectedMethods, RateForPath vb. alanlarınız varsa ekleyin:
	// ProtectedMethods []string
}

// IPRateLimiter, IP bazlı rate limiting mekanizması tutar.
type IPRateLimiter struct {
	config RateLimiterConfig
	mu     sync.Mutex
	bucket map[string]*rate.Limiter
}

// NewIPRateLimiter, RateLimiterConfig ile yeni bir limiter örneği döner.
func NewIPRateLimiter(cfg RateLimiterConfig) *IPRateLimiter {
	return &IPRateLimiter{
		config: cfg,
		bucket: make(map[string]*rate.Limiter),
	}
}

// getLimiter, verilen IP için uygun rate.Limiter'ı döner (yoksa oluşturur)
func (r *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	lim, exists := r.bucket[ip]
	if !exists {
		// Dakikaya göre Rate (dakikadaki istek sayısı / 60 = saniyedeki istek sayısı)
		ratePerSecond := rate.Limit(float64(r.config.MaxRequestsPerMinute) / 60.0)
		lim = rate.NewLimiter(ratePerSecond, r.config.Burst)
		r.bucket[ip] = lim
	}

	return lim
}

// cleanupTask, belirli aralıklarla hiç istek atılmayan IP'leri siler.
func (r *IPRateLimiter) cleanupTask() {
	ticker := time.NewTicker(r.config.CleanupInterval)
	for range ticker.C {
		r.mu.Lock()
		for ip, lim := range r.bucket {
			// Eğer bu IP'nin bucket'ı boşsa (izinliyken hicbir işaret yoksa) silelim
			if lim.Allow() {
				delete(r.bucket, ip)
			}
		}
		r.mu.Unlock()
	}
}

// UnaryServerInterceptor, gRPC çağrılarında IP bazlı rate limit uygular.
func (r *IPRateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	// Temizleme görevini arka planda başlat
	go r.cleanupTask()

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 1) Context içinden metadata'da “x-forwarded-for” var mı bakalım
		var peerIP string
		if p, ok := peer.FromContext(ctx); ok {
			// peer.Addr.Format => e.g. "192.168.0.5:57432" => Sadece host kısmını ayıklıyoruz
			host, _, err := net.SplitHostPort(p.Addr.String())
			if err == nil {
				peerIP = host
			}
		}

		// 2) Eğer metadata içinde x-forwarded-for header varsa, onu öncelikli kullan
		//    (Load Balancer veya Proxy altında çalışıyorsanız gerekebilir)
		// md, _ := metadata.FromIncomingContext(ctx)
		// if len(md.Get("x-forwarded-for")) > 0 {
		//     peerIP = md.Get("x-forwarded-for")[0]
		// }

		// 3) Rate limiter'a IP’yi ver ve izin var mı kontrol et
		lim := r.getLimiter(peerIP)
		if !lim.Allow() {
			// ResourceExhausted = 8
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit aşıldı: IP=%s", peerIP)
		}

		// 4) İzin varsa, gerçek handler’ı çağır
		return handler(ctx, req)
	}
}
