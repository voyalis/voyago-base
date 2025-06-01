package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1" // Kendi proto paket yolunuz
)

const (
	authServiceAddrEnv     = "AUTH_SERVICE_ADDR_E2E_TEST" // CI'da set edilecek ortam değişkeni
	defaultAuthServiceAddr = "localhost:50051"            // Lokal testler için varsayılan
	defaultTestTimeout     = 60 * time.Second             // E2E testleri için genel timeout
)

var testAuthClient pb.AuthServiceClient // Testler arasında yeniden kullanılacak global client

// TestMain, tüm E2E testleri için bir kerelik gRPC bağlantısı kurar.
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
		grpc.WithBlock(),                 // Bağlantı kurulana kadar bekle
		grpc.WithTimeout(20*time.Second), // Bağlantı timeout'u
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

	testAuthClient = pb.NewAuthServiceClient(conn) // Global client'ı burada set ediyoruz
	fmt.Println("E2E_INFO: gRPC client initialized globally for E2E tests.")

	// Testleri çalıştır
	exitCode := m.Run()
	os.Exit(exitCode)
}

// TestAuthService_FullAuthFlow tüm ana kimlik doğrulama akışını test eder.
func TestAuthService_FullAuthFlow(t *testing.T) {
	require.NotNil(t, testAuthClient, "gRPC client must be initialized in TestMain") // Düzeltildi: testAuthClientGlobal -> testAuthClient

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	uniqueEmail := fmt.Sprintf("e2e_fullflow_%s@voyago.com", uuid.NewString()[:8])
	password := "E2eFullFlowPass123!"
	fullName := "E2E Full Flow User " + uuid.NewString()[:4]

	var registeredUserID string
	var initialLoginResponse *pb.LoginResponse
	var refreshedLoginResponse *pb.LoginResponse

	// --- 1. Register ---
	t.Run("Stage_RegisterNewUser", func(t *testing.T) {
		regReq := &pb.RegisterRequest{Email: uniqueEmail, Password: password, FullName: fullName}
		regRes, err := testAuthClient.Register(ctx, regReq) // Düzeltildi
		require.NoError(t, err, "Register RPC should not fail")
		require.NotNil(t, regRes); require.NotNil(t, regRes.User)
		assert.Equal(t, uniqueEmail, regRes.User.Email)
		assert.Contains(t, regRes.User.Roles, "passenger")
		assert.True(t, regRes.User.IsActive)
		assert.False(t, regRes.User.EmailVerified)
		registeredUserID = regRes.User.UserId
		t.Logf("E2E_INFO (FullAuthFlow): Register successful for %s, UserID: %s", uniqueEmail, registeredUserID)
	})
	require.NotEmpty(t, registeredUserID)

	// --- 2. Login ---
	t.Run("Stage_LoginUser", func(t *testing.T) {
		loginReq := &pb.LoginRequest{Email: uniqueEmail, Password: password}
		var err error
		initialLoginResponse, err = testAuthClient.Login(ctx, loginReq) // Düzeltildi
		require.NoError(t, err, "Login RPC should not fail")
		require.NotNil(t, initialLoginResponse); require.NotEmpty(t, initialLoginResponse.AccessToken); require.NotEmpty(t, initialLoginResponse.RefreshToken)
		t.Logf("E2E_INFO (FullAuthFlow): Login successful for %s.", uniqueEmail)
	})
	require.NotNil(t, initialLoginResponse)

	// --- 3. Validate Access Token ---
	t.Run("Stage_ValidateAccessToken", func(t *testing.T) {
		valReq := &pb.ValidateTokenRequest{Token: initialLoginResponse.AccessToken}
		valRes, err := testAuthClient.ValidateToken(ctx, valReq) // Düzeltildi
		require.NoError(t, err, "ValidateToken RPC should not fail")
		require.NotNil(t, valRes); require.NotNil(t, valRes.User)
		assert.Equal(t, registeredUserID, valRes.User.UserId)
		t.Logf("E2E_INFO (FullAuthFlow): ValidateAccessToken successful for UserID: %s", valRes.User.UserId)
	})

	// --- 4. Refresh Access Token ---
	t.Run("Stage_RefreshAccessToken", func(t *testing.T) {
		refreshReq := &pb.RefreshAccessTokenRequest{RefreshToken: initialLoginResponse.RefreshToken}
		var err error
		refreshedLoginResponse, err = testAuthClient.RefreshAccessToken(ctx, refreshReq) // Düzeltildi
		require.NoError(t, err, "RefreshAccessToken RPC should not fail")
		require.NotNil(t, refreshedLoginResponse); require.NotEmpty(t, refreshedLoginResponse.AccessToken); require.NotEmpty(t, refreshedLoginResponse.RefreshToken)
		assert.NotEqual(t, initialLoginResponse.AccessToken, refreshedLoginResponse.AccessToken)
		assert.NotEqual(t, initialLoginResponse.RefreshToken, refreshedLoginResponse.RefreshToken)
		t.Logf("E2E_INFO (FullAuthFlow): RefreshAccessToken successful for UserID: %s", refreshedLoginResponse.User.UserId)
	})
	require.NotNil(t, refreshedLoginResponse)

	// --- 5. Logout ---
	t.Run("Stage_LogoutUser", func(t *testing.T) {
		logoutReq := &pb.LogoutRequest{RefreshToken: refreshedLoginResponse.RefreshToken}
		logoutRes, err := testAuthClient.Logout(ctx, logoutReq) // Düzeltildi
		require.NoError(t, err, "Logout RPC should not fail")
		require.NotNil(t, logoutRes); assert.Contains(t, logoutRes.Message, "revoked")
		t.Logf("E2E_INFO (FullAuthFlow): Logout successful for UserID: %s", refreshedLoginResponse.User.UserId)

		_, errRefreshAfterLogout := testAuthClient.RefreshAccessToken(ctx, &pb.RefreshAccessTokenRequest{RefreshToken: refreshedLoginResponse.RefreshToken}) // Düzeltildi
		require.Error(t, errRefreshAfterLogout); st, ok := status.FromError(errRefreshAfterLogout); require.True(t, ok); assert.Equal(t, codes.Unauthenticated, st.Code())
		t.Logf("E2E_INFO (FullAuthFlow): Attempt to refresh revoked token failed as expected: %v", errRefreshAfterLogout)
	})
}

// TestAuthService_PasswordResetRequestE2E şifre sıfırlama talebi RPC'sini test eder.
func TestAuthService_PasswordResetRequestE2E(t *testing.T) {
	require.NotNil(t, testAuthClient, "gRPC client must be initialized in TestMain") // Düzeltildi

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	userEmailForReset := fmt.Sprintf("e2e-pwd-req-%s@voyago.com", uuid.NewString()[:8])
	password := "PassResetE2E123!"
	fullName := "Pwd Reset Req User " + uuid.NewString()[:4]

	regReq := &pb.RegisterRequest{Email: userEmailForReset, Password: password, FullName: fullName}
	regRes, err := testAuthClient.Register(ctx, regReq) // Düzeltildi
	require.NoError(t, err, "PasswordResetRequestE2E: Register RPC failed")
	require.NotNil(t, regRes)
	t.Logf("E2E_INFO (PasswordResetRequestE2E): User registered for password reset request: %s, UserID: %s", userEmailForReset, regRes.User.UserId)

	reqResetReq := &pb.RequestPasswordResetRequest{Email: userEmailForReset}
	reqResetRes, err := testAuthClient.RequestPasswordReset(ctx, reqResetReq) // Düzeltildi
	require.NoError(t, err, "RequestPasswordReset RPC failed")
	require.NotNil(t, reqResetRes)
	assert.Contains(t, reqResetRes.Message, "If an account with that email exists, a password reset link has been sent")
	assert.True(t, reqResetRes.ExpiresInSeconds > 0)
	t.Logf("E2E_INFO (PasswordResetRequestE2E): Password reset requested for %s. Response message: %s", userEmailForReset, reqResetRes.Message)
}

// TestAuthService_EmailVerificationRequestE2E e-posta doğrulama talebi RPC'sini test eder.
func TestAuthService_EmailVerificationRequestE2E(t *testing.T) {
	require.NotNil(t, testAuthClient, "gRPC client must be initialized in TestMain") // Düzeltildi

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	userEmailForVerification := fmt.Sprintf("e2e-email-verif-%s@voyago.com", uuid.NewString()[:8])
	password := "EmailVerifE2E123!"
	fullName := "Email Verif Req User " + uuid.NewString()[:4]

	regReq := &pb.RegisterRequest{Email: userEmailForVerification, Password: password, FullName: fullName}
	_, err := testAuthClient.Register(ctx, regReq) // Düzeltildi
	require.NoError(t, err, "EmailVerificationRequestE2E: Register RPC failed")
	t.Logf("E2E_INFO (EmailVerificationRequestE2E): User registered for email verification request: %s", userEmailForVerification)

	loginReq := &pb.LoginRequest{Email: userEmailForVerification, Password: password}
	loginRes, err := testAuthClient.Login(ctx, loginReq) // Düzeltildi
	require.NoError(t, err, "EmailVerificationRequestE2E: Login RPC failed")
	require.NotNil(t, loginRes); require.NotEmpty(t, loginRes.AccessToken)
	t.Logf("E2E_INFO (EmailVerificationRequestE2E): Logged in to get access token for %s", userEmailForVerification)

	reqEmailVerifReq := &pb.RequestEmailVerificationRequest{AccessToken: loginRes.AccessToken}
	reqEmailVerifRes, err := testAuthClient.RequestEmailVerification(ctx, reqEmailVerifReq) // Düzeltildi
	require.NoError(t, err, "RequestEmailVerification RPC failed")
	require.NotNil(t, reqEmailVerifRes)
	assert.Contains(t, reqEmailVerifRes.Message, "A verification link has been sent to your email address")
	assert.True(t, reqEmailVerifRes.ExpiresInSeconds > 0)
	t.Logf("E2E_INFO (EmailVerificationRequestE2E): Email verification requested for %s. Response message: %s", userEmailForVerification, reqEmailVerifRes.Message)
}

// TestAuthService_UpdateUserMetadataE2E, kullanıcının profil bilgilerini (full_name) güncelleme akışını test eder.
func TestAuthService_UpdateUserMetadataE2E(t *testing.T) {
	require.NotNil(t, testAuthClient, "gRPC client must be initialized in TestMain")

	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()

	// 1. Test için yeni bir kullanıcı oluştur
	userEmailForMetadata := fmt.Sprintf("e2e-metadata-%s@voyago.com", uuid.NewString()[:8])
	password := "MetadataE2E123$"
	initialFullName := "Initial E2E Name " + uuid.NewString()[:4]

	regReq := &pb.RegisterRequest{Email: userEmailForMetadata, Password: password, FullName: initialFullName}
	regRes, err := testAuthClient.Register(ctx, regReq)
	require.NoError(t, err, "UpdateUserMetadataE2E: Register RPC failed")
	require.NotNil(t, regRes); require.NotNil(t, regRes.User)
	registeredUserID := regRes.User.UserId
	t.Logf("E2E_INFO (UpdateUserMetadataE2E): User registered: %s, UserID: %s, Initial FullName: %s", userEmailForMetadata, registeredUserID, initialFullName)

	// 2. Login ol ve access token al
	loginReq := &pb.LoginRequest{Email: userEmailForMetadata, Password: password}
	loginRes, err := testAuthClient.Login(ctx, loginReq)
	require.NoError(t, err, "UpdateUserMetadataE2E: Login RPC failed")
	require.NotNil(t, loginRes); require.NotEmpty(t, loginRes.AccessToken)
	t.Logf("E2E_INFO (UpdateUserMetadataE2E): Logged in for %s. AccessToken acquired.", userEmailForMetadata)

	// 3. UpdateUserMetadata RPC'sini çağırarak full_name'i güncelle
	newFullName := "Updated E2E FullName " + uuid.NewString()[:4]
	updateReq := &pb.UpdateUserMetadataRequest{
		AccessToken: loginRes.AccessToken,
		FullName:    newFullName,
	}
	updateRes, err := testAuthClient.UpdateUserMetadata(ctx, updateReq)
	require.NoError(t, err, "UpdateUserMetadata RPC failed")
	require.NotNil(t, updateRes); require.NotNil(t, updateRes.User)
	assert.Equal(t, registeredUserID, updateRes.User.UserId)
	assert.Equal(t, newFullName, updateRes.User.FullName, "FullName in UpdateUserMetadataResponse should be the new name")
	assert.True(t, updateRes.User.EmailVerified == regRes.User.EmailVerified, "EmailVerified status should not change") // E-posta doğrulama durumu değişmemeli
	t.Logf("E2E_INFO (UpdateUserMetadataE2E): User metadata updated for UserID: %s. New FullName: %s", registeredUserID, updateRes.User.FullName)

	// 4. Güncellemenin kalıcı olduğunu doğrulamak için tekrar ValidateToken veya Login ile kontrol et
	// Yeni bir ValidateToken çağrısı yapalım
	validateReq := &pb.ValidateTokenRequest{Token: loginRes.AccessToken} // Aynı access token hala geçerli olmalı
	validateRes, err := testAuthClient.ValidateToken(ctx, validateReq)
	require.NoError(t, err, "ValidateToken RPC failed after metadata update")
	require.NotNil(t, validateRes); require.NotNil(t, validateRes.User)
	assert.Equal(t, registeredUserID, validateRes.User.UserId)
	assert.Equal(t, newFullName, validateRes.User.FullName, "FullName in validated token info should be the new name")
	t.Logf("E2E_INFO (UpdateUserMetadataE2E): Validated token after metadata update, FullName is correct: %s", validateRes.User.FullName)

	// Alternatif: Yeni bir login ile de kontrol edilebilir (yeni bir access token alınır)
	// loginAgainReq := &pb.LoginRequest{Email: userEmailForMetadata, Password: password}
	// loginAgainRes, errLoginAgain := testAuthClient.Login(ctx, loginAgainReq)
	// require.NoError(t, errLoginAgain, "Login again RPC failed after metadata update")
	// require.NotNil(t, loginAgainRes); require.NotNil(t, loginAgainRes.User)
	// assert.Equal(t, newFullName, loginAgainRes.User.FullName, "FullName in new login response should be the new name")
	// t.Logf("E2E_INFO (UpdateUserMetadataE2E): Logged in again, FullName is correct: %s", loginAgainRes.User.FullName)
}