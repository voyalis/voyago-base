package interceptor

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestIPRateLimiter_GetLimiter(t *testing.T) {
	config := RateLimiterConfig{RequestsPerSecond: 1, Burst: 1}
	rl := NewIPRateLimiter(config)

	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	limiter1a := rl.GetLimiter(ip1)
	require.NotNil(t, limiter1a)

	limiter1b := rl.GetLimiter(ip1)
	assert.Same(t, limiter1a, limiter1b, "Should return the same limiter for the same IP")

	limiter2 := rl.GetLimiter(ip2)
	require.NotNil(t, limiter2)
	assert.NotSame(t, limiter1a, limiter2, "Should return different limiters for different IPs")
}

func TestIPRateLimiter_UnaryServerInterceptor_Allow(t *testing.T) {
	config := RateLimiterConfig{
		RequestsPerSecond: 1, // Saniyede 1 istek
		Burst:             1,   // Anlık 1 istek
		ProtectedMethods:  map[string]bool{"/test.Service/ProtectedMethod": true},
	}
	rl := NewIPRateLimiter(config)
	interceptor := rl.UnaryServerInterceptor()

	// Sahte peer bilgisi oluştur
	dummyAddr := &net.IPAddr{IP: net.ParseIP("123.123.123.123")}
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: dummyAddr})
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/ProtectedMethod"}
	dummyHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	// İlk istek başarılı olmalı
	_, err := interceptor(ctx, "request", info, dummyHandler)
	assert.NoError(t, err, "First request should be allowed")

	// İkinci istek (burst dolduğu için) hemen ResourceExhausted vermeli
	_, err = interceptor(ctx, "request", info, dummyHandler)
	require.Error(t, err, "Second request should be rate limited")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.Contains(t, st.Message(), "too many requests")
}

func TestIPRateLimiter_UnaryServerInterceptor_NonProtectedMethod(t *testing.T) {
	config := RateLimiterConfig{
		RequestsPerSecond: 1, Burst: 1,
		ProtectedMethods: map[string]bool{"/test.Service/ProtectedMethod": true}, // Sadece bu korunuyor
	}
	rl := NewIPRateLimiter(config)
	interceptor := rl.UnaryServerInterceptor()
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.IPAddr{IP: net.ParseIP("1.1.1.1")}})
	info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/UnprotectedMethod"} // Korunmayan metot
	dummyHandler := func(ctx context.Context, req interface{}) (interface{}, error) { return "response", nil }

	// Birden fazla istek başarılı olmalı çünkü metot korunmuyor
	_, err := interceptor(ctx, "request", info, dummyHandler)
	assert.NoError(t, err)
	_, err = interceptor(ctx, "request", info, dummyHandler)
	assert.NoError(t, err)
}