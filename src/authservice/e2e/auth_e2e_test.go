package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require" // require.NoError vb. için
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure" // grpc.WithInsecure() yerine
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/src/authservice/genproto" // Kendi proto paket yolunuz
)

const (
	authServiceAddrEnv = "AUTH_SERVICE_ADDR_E2E_TEST" // CI'da set edilecek ortam değişkeni
	defaultAuthServiceAddr = "localhost:50051"         // Lokal testler için varsayılan
)

// getClient, testler için bir AuthService gRPC istemcisi oluşturur.
func getClient(t *testing.T) pb.AuthServiceClient {
	addr := os.Getenv(authServiceAddrEnv)
	if addr == "" {
		addr = defaultAuthServiceAddr
		t.Logf("Environment variable %s not set, using default: %s", authServiceAddrEnv, addr)
	} else {
		t.Logf("Using AuthService address from env %s: %s", authServiceAddrEnv, addr)
	}

	// grpc.WithInsecure() deprecated oldu, grpc.WithTransportCredentials(insecure.NewCredentials()) kullanılıyor.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithTimeout(10*time.Second))
	require.NoError(t, err, "gRPC Dial failed")

	// Test bittiğinde bağlantıyı kapatmak için t.Cleanup kullanmak iyi bir pratiktir.
	t.Cleanup(func() {
		err := conn.Close()
		if err != nil {
			t.Logf("Error closing gRPC connection: %v", err)
		}
	})

	return pb.NewAuthServiceClient(conn)
}

// TestAuthService_EndToEndFlow tüm ana kimlik doğrulama akışını test eder.
func TestAuthService_EndToEndFlow(t *testing.T) {
	// Bu testi CI'da koşarken, AUTH_SERVICE_ADDR_E2E_TEST ortam değişkeninin
	// CI'daki Minikube AuthService servisine port-forward edilmiş adresi göstermesi gerekir.
	// Lokal testler için localhost:50051 varsayılır.

	client := getClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute) // Test için genel bir timeout
	defer cancel()

	// Her test çalıştığında benzersiz bir e-posta kullanmak için
	uniqueEmail := fmt.Sprintf("e2e_user_%s@voyago.com", uuid.NewString()[:8])
	password := "E2eStrongPass123!"
	fullName := "E2E Test User"

	// --- 1. Register ---
	t.Run("RegisterNewUser", func(t *testing.T) {
		regReq := &pb.RegisterRequest{Email: uniqueEmail, Password: password, FullName: fullName}
		regRes, err := client.Register(ctx, regReq)
		require.NoError(t, err, "Register RPC failed")
		require.NotNil(t, regRes, "RegisterResponse should not be nil")
		require.NotNil(t, regRes.User, "RegisterResponse.User should not be nil")
		assert.Equal(t, uniqueEmail, regRes.User.Email, "Registered email mismatch")
		assert.Contains(t, regRes.User.Roles, "passenger", "Default role should be passenger")
		t.Logf("Register successful for %s, UserID: %s", uniqueEmail, regRes.User.UserId)
	})

	var loginRes *pb.LoginResponse // Login ve Refresh'ten gelen tokenları saklamak için
	var errLogin error

	// --- 2. Login ---
	t.Run("LoginUser", func(t *testing.T) {
		loginReq := &pb.LoginRequest{Email: uniqueEmail, Password: password}
		loginRes, errLogin = client.Login(ctx, loginReq)
		require.NoError(t, errLogin, "Login RPC failed")
		require.NotNil(t, loginRes, "LoginResponse should not be nil")
		require.NotEmpty(t, loginRes.AccessToken, "AccessToken should not be empty")
		require.NotEmpty(t, loginRes.RefreshToken, "RefreshToken should not be empty")
		require.NotNil(t, loginRes.User, "LoginResponse.User should not be nil")
		assert.Equal(t, uniqueEmail, loginRes.User.Email, "Logged in email mismatch")
		t.Logf("Login successful for %s. AccessToken (first 10): %s...", uniqueEmail, loginRes.AccessToken[:min(10, len(loginRes.AccessToken))])
	})

	// Login başarılı olduysa devam et
	if errLogin != nil {
		t.Fatalf("Cannot proceed with E2E tests as Login failed: %v", errLogin)
	}

	// --- 3. Validate Access Token ---
	t.Run("ValidateAccessToken", func(t *testing.T) {
		valReq := &pb.ValidateTokenRequest{Token: loginRes.AccessToken}
		valRes, err := client.ValidateToken(ctx, valReq)
		require.NoError(t, err, "ValidateToken RPC failed")
		require.NotNil(t, valRes, "ValidateTokenResponse should not be nil")
		require.NotNil(t, valRes.User, "ValidateTokenResponse.User should not be nil")
		assert.Equal(t, loginRes.User.UserId, valRes.User.UserId, "Validated UserID mismatch")
		assert.Equal(t, uniqueEmail, valRes.User.Email, "Validated email mismatch")
		assert.True(t, valRes.User.IsActive, "User should be active")
		t.Logf("ValidateAccessToken successful for UserID: %s", valRes.User.UserId)
	})

	// --- 4. Refresh Access Token ---
	var refreshedLoginRes *pb.LoginResponse
	var errRefresh error
	t.Run("RefreshAccessToken", func(t *testing.T) {
		refreshReq := &pb.RefreshAccessTokenRequest{RefreshToken: loginRes.RefreshToken}
		refreshedLoginRes, errRefresh = client.RefreshAccessToken(ctx, refreshReq)
		require.NoError(t, errRefresh, "RefreshAccessToken RPC failed")
		require.NotNil(t, refreshedLoginRes, "Refreshed LoginResponse should not be nil")
		require.NotEmpty(t, refreshedLoginRes.AccessToken, "New AccessToken should not be empty")
		require.NotEmpty(t, refreshedLoginRes.RefreshToken, "New RefreshToken should not be empty")
		assert.NotEqual(t, loginRes.AccessToken, refreshedLoginRes.AccessToken, "AccessToken should be new")
		assert.NotEqual(t, loginRes.RefreshToken, refreshedLoginRes.RefreshToken, "RefreshToken should be new (rotated)")
		require.NotNil(t, refreshedLoginRes.User, "Refreshed LoginResponse.User should not be nil")
		assert.Equal(t, loginRes.User.UserId, refreshedLoginRes.User.UserId, "Refreshed UserID mismatch")
		t.Logf("RefreshAccessToken successful for UserID: %s. New AccessToken (first 10): %s...", refreshedLoginRes.User.UserId, refreshedLoginRes.AccessToken[:min(10, len(refreshedLoginRes.AccessToken))])
	})
	
	if errRefresh != nil {
		t.Fatalf("Cannot proceed with Logout test as RefreshAccessToken failed: %v", errRefresh)
	}

	// --- 5. Logout ---
	t.Run("LogoutUser", func(t *testing.T) {
		// Yenilenmiş refresh token'ı kullanalım
		logoutReq := &pb.LogoutRequest{RefreshToken: refreshedLoginRes.RefreshToken}
		logoutRes, err := client.Logout(ctx, logoutReq)
		require.NoError(t, err, "Logout RPC failed")
		require.NotNil(t, logoutRes, "LogoutResponse should not be nil")
		assert.Contains(t, logoutRes.Message, "revoked", "Logout message should indicate token revocation")
		t.Logf("Logout successful for UserID: %s", refreshedLoginRes.User.UserId)

		// İptal edilmiş refresh token ile tekrar yenileme denemesi (hata vermeli)
		_, errRefreshAfterLogout := client.RefreshAccessToken(ctx, &pb.RefreshAccessTokenRequest{RefreshToken: refreshedLoginRes.RefreshToken})
		require.Error(t, errRefreshAfterLogout, "RefreshAccessToken should fail with a revoked token")
		st, ok := status.FromError(errRefreshAfterLogout)
		require.True(t, ok, "Error should be a gRPC status error after trying to refresh revoked token")
		assert.Equal(t, codes.Unauthenticated, st.Code(), "gRPC error code should be Unauthenticated for revoked refresh token")
		t.Logf("Attempt to refresh revoked token failed as expected: %v", errRefreshAfterLogout)
	})
}

// min helper (eğer bu pakette de gerekirse)
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}