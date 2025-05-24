package e2e

import (
	"context"
	"fmt"
	"os" // Hata mesajı kontrolü için
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/src/authservice/genproto" // Kendi proto paket yolunuz
)

const (
	authServiceAddrEnv     = "AUTH_SERVICE_ADDR_E2E_TEST" // CI'da set edilecek ortam değişkeni
	defaultAuthServiceAddr = "localhost:50051"            // Lokal testler için varsayılan
	defaultTestTimeout     = 30 * time.Second             // E2E testleri için genel timeout
)

var testAuthClient pb.AuthServiceClient // Testler arasında yeniden kullanılacak client

// TestMain, E2E testleri için bir kerelik gRPC bağlantısı kurar.
func TestMain(m *testing.M) {
	addr := os.Getenv(authServiceAddrEnv)
	if addr == "" {
		addr = defaultAuthServiceAddr
		fmt.Printf("E2E_INFO: Environment variable %s not set, using default: %s\n", authServiceAddrEnv, addr)
	} else {
		fmt.Printf("E2E_INFO: Using AuthService address from env %s: %s\n", authServiceAddrEnv, addr)
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), // Bağlantı kurulana kadar bekle
		grpc.WithTimeout(15*time.Second), // Bağlantı timeout'u
	)
	if err != nil {
		fmt.Printf("E2E_FATAL: gRPC Dial failed during TestMain setup: %v\n", err)
		os.Exit(1) // Bağlantı kurulamazsa testler çalışamaz
	}
	defer func() {
		fmt.Println("E2E_INFO: Closing gRPC connection in TestMain.")
		if err := conn.Close(); err != nil {
			fmt.Printf("E2E_WARN: Error closing gRPC connection: %v\n", err)
		}
	}()

	testAuthClient = pb.NewAuthServiceClient(conn)
	fmt.Println("E2E_INFO: gRPC client initialized for tests.")

	// Testleri çalıştır
	exitCode := m.Run()
	os.Exit(exitCode)
}

// TestAuthService_EndToEndFlow tüm ana kimlik doğrulama akışını test eder.
func TestAuthService_EndToEndFlow(t *testing.T) {
	require.NotNil(t, testAuthClient, "gRPC client must be initialized in TestMain")

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	// Her test çalıştığında benzersiz bir e-posta kullanmak için
	uniqueEmail := fmt.Sprintf("e2e_user_%s@voyago.com", uuid.NewString()[:12]) // Daha kısa bir UUID
	password := "E2eValidPass123!"
	fullName := "E2E Test User " + uuid.NewString()[:4]

	var registeredUserID string
	var initialLoginResponse *pb.LoginResponse
	var refreshedLoginResponse *pb.LoginResponse

	// --- 1. Register ---
	t.Run("RegisterNewUser", func(t *testing.T) {
		regReq := &pb.RegisterRequest{Email: uniqueEmail, Password: password, FullName: fullName}
		regRes, err := testAuthClient.Register(ctx, regReq)
		require.NoError(t, err, "Register RPC should not fail")
		require.NotNil(t, regRes, "RegisterResponse should not be nil")
		require.NotNil(t, regRes.User, "RegisterResponse.User should not be nil")
		assert.Equal(t, uniqueEmail, regRes.User.Email, "Registered email mismatch")
		assert.Contains(t, regRes.User.Roles, "passenger", "Default role should be passenger")
		assert.True(t, regRes.User.IsActive, "User should be active upon registration")
		assert.False(t, regRes.User.EmailVerified, "Email should not be verified upon registration")
		registeredUserID = regRes.User.UserId // Sonraki adımlar için sakla
		t.Logf("E2E: Register successful for %s, UserID: %s", uniqueEmail, registeredUserID)
	})

	// Register başarılı olduysa devam et
	require.NotEmpty(t, registeredUserID, "UserID must be set after successful registration to proceed")

	// --- 2. Login ---
	t.Run("LoginUser", func(t *testing.T) {
		loginReq := &pb.LoginRequest{Email: uniqueEmail, Password: password}
		var err error
		initialLoginResponse, err = testAuthClient.Login(ctx, loginReq)
		require.NoError(t, err, "Login RPC should not fail")
		require.NotNil(t, initialLoginResponse, "LoginResponse should not be nil")
		require.NotEmpty(t, initialLoginResponse.AccessToken, "AccessToken should not be empty")
		require.NotEmpty(t, initialLoginResponse.RefreshToken, "RefreshToken should not be empty")
		require.NotNil(t, initialLoginResponse.User, "LoginResponse.User should not be nil")
		assert.Equal(t, registeredUserID, initialLoginResponse.User.UserId, "Logged in UserID mismatch")
		assert.Equal(t, uniqueEmail, initialLoginResponse.User.Email, "Logged in email mismatch")
		t.Logf("E2E: Login successful for %s.", uniqueEmail)
	})

	require.NotNil(t, initialLoginResponse, "Initial LoginResponse is nil, cannot proceed")
	require.NotEmpty(t, initialLoginResponse.AccessToken, "Initial AccessToken is empty, cannot proceed")
	require.NotEmpty(t, initialLoginResponse.RefreshToken, "Initial RefreshToken is empty, cannot proceed")


	// --- 3. Validate Access Token ---
	t.Run("ValidateAccessToken", func(t *testing.T) {
		valReq := &pb.ValidateTokenRequest{Token: initialLoginResponse.AccessToken}
		valRes, err := testAuthClient.ValidateToken(ctx, valReq)
		require.NoError(t, err, "ValidateToken RPC should not fail with a valid token")
		require.NotNil(t, valRes, "ValidateTokenResponse should not be nil")
		require.NotNil(t, valRes.User, "ValidateTokenResponse.User should not be nil")
		assert.Equal(t, registeredUserID, valRes.User.UserId, "Validated UserID mismatch")
		assert.True(t, valRes.User.IsActive, "User should be active")
		t.Logf("E2E: ValidateAccessToken successful for UserID: %s", valRes.User.UserId)
	})

	// --- 4. Refresh Access Token ---
	t.Run("RefreshAccessToken", func(t *testing.T) {
		require.NotNil(t, initialLoginResponse, "Initial LoginResponse is nil for RefreshAccessToken step")
		require.NotEmpty(t, initialLoginResponse.RefreshToken, "Initial RefreshToken is empty for RefreshAccessToken step")

		refreshReq := &pb.RefreshAccessTokenRequest{RefreshToken: initialLoginResponse.RefreshToken}
		var err error
		refreshedLoginResponse, err = testAuthClient.RefreshAccessToken(ctx, refreshReq)
		require.NoError(t, err, "RefreshAccessToken RPC should not fail with a valid refresh token")
		require.NotNil(t, refreshedLoginResponse, "Refreshed LoginResponse should not be nil")
		require.NotEmpty(t, refreshedLoginResponse.AccessToken, "New AccessToken should not be empty")
		require.NotEmpty(t, refreshedLoginResponse.RefreshToken, "New RefreshToken should not be empty")
		
		t.Logf("E2E: Initial AccessToken: %s", initialLoginResponse.AccessToken)
		t.Logf("E2E: Refreshed AccessToken: %s", refreshedLoginResponse.AccessToken)
		t.Logf("E2E: Initial RefreshToken: %s", initialLoginResponse.RefreshToken)
		t.Logf("E2E: Refreshed RefreshToken: %s", refreshedLoginResponse.RefreshToken)

		assert.NotEqual(t, initialLoginResponse.AccessToken, refreshedLoginResponse.AccessToken, "AccessToken should be new after refresh")
		assert.NotEqual(t, initialLoginResponse.RefreshToken, refreshedLoginResponse.RefreshToken, "RefreshToken should be new (rotated) after refresh")
		
		require.NotNil(t, refreshedLoginResponse.User, "Refreshed LoginResponse.User should not be nil")
		assert.Equal(t, initialLoginResponse.User.UserId, refreshedLoginResponse.User.UserId, "Refreshed UserID mismatch")
		t.Logf("E2E: RefreshAccessToken successful for UserID: %s", refreshedLoginResponse.User.UserId)
	})

	require.NotNil(t, refreshedLoginResponse, "Refreshed LoginResponse is nil, cannot proceed with Logout")
	require.NotEmpty(t, refreshedLoginResponse.RefreshToken, "Refreshed RefreshToken is empty, cannot proceed with Logout")

	// --- 5. Logout ---
	t.Run("LogoutUser", func(t *testing.T) {
		logoutReq := &pb.LogoutRequest{RefreshToken: refreshedLoginResponse.RefreshToken} // Yenilenmiş refresh token'ı kullan
		logoutRes, err := testAuthClient.Logout(ctx, logoutReq)
		require.NoError(t, err, "Logout RPC should not fail")
		require.NotNil(t, logoutRes, "LogoutResponse should not be nil")
		assert.Contains(t, logoutRes.Message, "revoked", "Logout message should indicate token revocation")
		t.Logf("E2E: Logout successful for UserID: %s", refreshedLoginResponse.User.UserId)

		// İptal edilmiş refresh token ile tekrar yenileme denemesi (hata vermeli)
		_, errRefreshAfterLogout := testAuthClient.RefreshAccessToken(ctx, &pb.RefreshAccessTokenRequest{RefreshToken: refreshedLoginResponse.RefreshToken})
		require.Error(t, errRefreshAfterLogout, "RefreshAccessToken should fail with a revoked token")
		st, ok := status.FromError(errRefreshAfterLogout)
		require.True(t, ok, "Error should be a gRPC status error after trying to refresh revoked token")
		assert.Equal(t, codes.Unauthenticated, st.Code(), "gRPC error code should be Unauthenticated for revoked refresh token")
		t.Logf("E2E: Attempt to refresh revoked token failed as expected: %v", errRefreshAfterLogout)
	})
}

// min helper (eğer bu pakette de gerekirse)
// func min(a, b int) int { if a < b { return a }; return b }