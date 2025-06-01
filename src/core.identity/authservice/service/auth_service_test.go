package service

// auth_service_test.go
import (
	"context"
	"database/sql" // MockUserRepository'de repository.User.FullName için sql.NullString
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt" // Login testinde şifre hash'lemek için
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
	"github.com/voyalis/voyago-base/src/core.identity/authservice/interceptor" // RateLimiterConfig için
	"github.com/voyalis/voyago-base/src/core.identity/authservice/repository"
	"golang.org/x/time/rate" // RateLimiterConfig için
)

// MockUserRepository, UserRepository interface'ini mock'lar.
type MockUserRepository struct {
	mock.Mock
}

// Bu satır, MockUserRepository'nin gerçekten UserRepository interface'ini
// (bu service paketinde tanımlı olan) implemente edip etmediğini derleme zamanında kontrol eder.
var _ UserRepository = (*MockUserRepository)(nil)

// --- MockUserRepository Metot Implementasyonları (TÜM METOTLAR DAHİL) ---
func (m *MockUserRepository) CreateUser(ctx context.Context, email, passwordHash, fullName string) (*repository.User, error) {
	args := m.Called(ctx, email, passwordHash, fullName)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*repository.User), args.Error(1)
}
func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error) {
	args := m.Called(ctx, email)
	var ui *pb.UserInfo; if args.Get(0) != nil { ui = args.Get(0).(*pb.UserInfo) }; return ui, args.String(1), args.Bool(2), args.Error(3)
}
func (m *MockUserRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*pb.UserInfo), args.Error(1)
}
func (m *MockUserRepository) StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt); return args.Error(0)
}
func (m *MockUserRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	args := m.Called(ctx, tokenHash); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*repository.RefreshToken), args.Error(1)
}
func (m *MockUserRepository) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash); return args.Error(0)
}
func (m *MockUserRepository) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID); return args.Error(0)
}
func (m *MockUserRepository) UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID); return args.Error(0)
}
func (m *MockUserRepository) StorePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt); return args.Error(0)
}
func (m *MockUserRepository) GetValidPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*repository.PasswordResetToken, error) {
	args := m.Called(ctx, tokenHash); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*repository.PasswordResetToken), args.Error(1)
}
func (m *MockUserRepository) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash); return args.Error(0)
}
func (m *MockUserRepository) UpdateUserPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	args := m.Called(ctx, userID, newPasswordHash); return args.Error(0)
}
func (m *MockUserRepository) StoreEmailVerificationToken(ctx context.Context, userID uuid.UUID, email string, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, email, tokenHash, expiresAt); return args.Error(0)
}
func (m *MockUserRepository) GetValidEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*repository.EmailVerificationToken, error) {
	args := m.Called(ctx, tokenHash); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*repository.EmailVerificationToken), args.Error(1)
}
func (m *MockUserRepository) MarkEmailVerificationTokenAsUsed(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash); return args.Error(0)
}
func (m *MockUserRepository) MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID); return args.Error(0)
}
func (m *MockUserRepository) UpdateUserFullName(ctx context.Context, userID uuid.UUID, newFullName string) error {
	args := m.Called(ctx, userID, newFullName); return args.Error(0)
}

// Helper: Varsayılan bir RateLimiterConfig oluşturur (unit testler için)
func newTestRateLimiterConfig() interceptor.RateLimiterConfig {
	return interceptor.RateLimiterConfig{
		RequestsPerSecond: rate.Limit(1000), // Testler için yüksek limit, rate limiting'i test etmiyorsak
		Burst:             2000,
		ProtectedMethods:  map[string]bool{}, // Bu test dosyasında rate limiting'i değil, RPC'leri test ediyoruz
		CleanupInterval:   0,                 // Testlerde cleanup goroutine'i başlatma
	}
}

// --- Test Fonksiyonları ---

func TestAuthServiceServer_Register_Success(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test-jwt-secret-for-authservice"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // rlConfig EKLENDİ
	req := &pb.RegisterRequest{Email: "newuser.service@example.com", Password: "SecurePassword123$", FullName: "Service Test User"}
	mockedRepoUserID := uuid.New()
	mockedRepoUser := &repository.User{ID: mockedRepoUserID, Email: req.Email, FullName: sql.NullString{String: req.FullName, Valid: true}, IsActive: true, EmailVerified: false}
	mockRepo.On("CreateUser", mock.Anything, req.Email, mock.AnythingOfType("string"), req.FullName).Return(mockedRepoUser, nil).Once()
	expectedPbUserInfo := &pb.UserInfo{UserId: mockedRepoUserID.String(), Email: req.Email, FullName: req.FullName, Roles: []string{"passenger"}, IsActive: true, EmailVerified: false}
	mockRepo.On("GetUserByID", mock.Anything, mockedRepoUserID).Return(expectedPbUserInfo, nil).Once()
	res, err := authService.Register(context.Background(), req)
	assert.NoError(t, err); require.NotNil(t, res); require.NotNil(t, res.User); assert.Equal(t, expectedPbUserInfo.UserId, res.User.UserId)
	assert.Equal(t, "User registered successfully", res.Message); mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_EmailAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_key"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	req := &pb.RegisterRequest{Email: "exists.service@example.com", Password: "password123", FullName: "Existing Service User"}
	mockRepo.On("CreateUser", mock.Anything, req.Email, mock.AnythingOfType("string"), req.FullName).Return(nil, fmt.Errorf("email '%s' already exists", req.Email)).Once()
	res, err := authService.Register(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res); st, ok := status.FromError(err); require.True(t, ok); assert.Equal(t, codes.AlreadyExists, st.Code())
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_Success(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_key_for_login_123"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	req := &pb.LoginRequest{Email: "logincandidate@example.com", Password: "ValidPassword123$"}
	mockUserID := uuid.New()
	mockPbUserInfoFromDB := &pb.UserInfo{UserId: mockUserID.String(), Email: req.Email, FullName: "Login Test User", Roles: []string{"passenger"}, IsActive: true, EmailVerified: true}
	hashedRealPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost); mockPasswordHash := string(hashedRealPassword)
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(mockPbUserInfoFromDB, mockPasswordHash, true, nil).Once()
	mockRepo.On("StoreRefreshToken", mock.Anything, mockUserID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()
	mockRepo.On("UpdateUserLastSignInAt", mock.Anything, mockUserID).Return(nil).Once()
	res, err := authService.Login(context.Background(), req)
	assert.NoError(t, err); require.NotNil(t, res); require.NotNil(t, res.User); assert.Equal(t, mockPbUserInfoFromDB.UserId, res.User.UserId); assert.NotEmpty(t, res.AccessToken); assert.NotEmpty(t, res.RefreshToken)
	token, jwtErr := jwt.Parse(res.AccessToken, func(token *jwt.Token) (interface{}, error) { return []byte(testJWTSecret), nil })
	assert.NoError(t, jwtErr); assert.True(t, token.Valid); claims, ok := token.Claims.(jwt.MapClaims); require.True(t, ok); assert.Equal(t, mockPbUserInfoFromDB.UserId, claims["sub"])
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_for_login_notfound"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	req := &pb.LoginRequest{Email: "notfound.service@example.com", Password: "AnyPassword123!"}
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(nil, "", false, fmt.Errorf("user with email '%s' not found", req.Email)).Once()
	res, err := authService.Login(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res); st, ok := status.FromError(err); require.True(t, ok); assert.Equal(t, codes.Unauthenticated, st.Code())
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_IncorrectPassword(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_for_login_wrongpass"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	req := &pb.LoginRequest{Email: "user.wrongpass@example.com", Password: "IncorrectPassword123!"}
	mockUserID := uuid.New();	mockPbUserInfoFromDB := &pb.UserInfo{UserId: mockUserID.String(), Email: req.Email, FullName: "User With Wrong Pass", Roles: []string{"passenger"}, IsActive: true, EmailVerified: true}
	hashedCorrectPassword, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword123!"), bcrypt.DefaultCost)
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(mockPbUserInfoFromDB, string(hashedCorrectPassword), true, nil).Once()
	res, err := authService.Login(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res); st, ok := status.FromError(err); require.True(t, ok); assert.Equal(t, codes.Unauthenticated, st.Code())
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_UserNotActive(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_for_login_inactive"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	req := &pb.LoginRequest{Email: "inactive.user@example.com", Password: "ValidPassword123!"}
	mockUserID := uuid.New();	mockPbUserInfoFromDB := &pb.UserInfo{UserId: mockUserID.String(), Email: req.Email, FullName: "Inactive User", Roles: []string{"passenger"}, IsActive: false, EmailVerified: true}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).Return(mockPbUserInfoFromDB, string(hashedPassword), false, nil).Once()
	res, err := authService.Login(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res); st, ok := status.FromError(err); require.True(t, ok); assert.Equal(t, codes.PermissionDenied, st.Code())
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ValidateToken_Success(t *testing.T) {
	mockRepo := new(MockUserRepository);	secret := "secret123_validate_success_v2"
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, secret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); userEmail := "e.validate.v2@x.com"; userRoles := []string{"passenger", "editor"}
	claims := jwt.MapClaims{"sub": userID.String(), "email": userEmail, "roles": userRoles, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims); signed, _ := token.SignedString([]byte(secret))
	pbInfo := &pb.UserInfo{UserId: userID.String(), Email: userEmail, IsActive: true, Roles: userRoles, FullName: "Validated User V2", EmailVerified: true}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(pbInfo, nil).Once()
	resp, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: signed})
	require.NoError(t, err); assert.Equal(t, userID.String(), resp.User.UserId); mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ValidateToken_InvalidSignature(t *testing.T) {
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(new(MockUserRepository), "actual_secret_key_validate_v2", rlConfig) // GÜNCELLENDİ
	claims := jwt.MapClaims{"sub": "user123_inv_sig_v2", "exp": time.Now().Add(time.Hour).Unix()};	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedWithWrongSecret, _ := token.SignedString([]byte("wrong_secret_key_for_sig_v2"))
	_, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: signedWithWrongSecret})
	st, _ := status.FromError(err); assert.Equal(t, codes.Unauthenticated, st.Code());	assert.Contains(t, st.Message(), "Invalid access token")
}

func TestAuthServiceServer_ValidateToken_Expired(t *testing.T) {
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(new(MockUserRepository), "secret_expired_validate_v2", rlConfig) // GÜNCELLENDİ
	claims := jwt.MapClaims{"sub": "user_exp_validate_v2", "email": "exp@v.com", "roles": []string{"p"}, "exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(), "jti": uuid.NewString()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims);	signedExpiredToken, _ := token.SignedString([]byte("secret_expired_validate_v2"))
	_, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: signedExpiredToken})
	st, _ := status.FromError(err); assert.Equal(t, codes.Unauthenticated, st.Code());	assert.Contains(t, st.Message(), "token is expired")
}

func TestAuthServiceServer_ValidateToken_UserInactive(t *testing.T) {
	mockRepo := new(MockUserRepository); secret := "secret_inactive_validate_v2"
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, secret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New();	claims := jwt.MapClaims{"sub": userID.String(), "email": "inactive.val.v2@v.com", "exp": time.Now().Add(time.Hour).Unix(), "jti": uuid.NewString()}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(&pb.UserInfo{UserId: userID.String(), IsActive: false}, nil).Once()
	_, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: tok})
	st, _ := status.FromError(err); assert.Equal(t, codes.PermissionDenied, st.Code()); assert.Contains(t, st.Message(), "User account is disabled")
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RefreshAccessToken_Success(t *testing.T) {
	mockRepo := new(MockUserRepository);	secret := "secret_refresh_success_v2"
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, secret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); rawOldRefreshToken := uuid.NewString(); hashedOldRefreshToken := hashToken(rawOldRefreshToken)
	dbToken := &repository.RefreshToken{UserID: userID, TokenHash: hashedOldRefreshToken, ExpiresAt: time.Now().Add(time.Hour)}
	mockRepo.On("GetRefreshTokenByHash", mock.Anything, hashedOldRefreshToken).Return(dbToken, nil).Once()
	mockRepo.On("RevokeRefreshTokenByHash", mock.Anything, hashedOldRefreshToken).Return(nil).Once()
	pbInfo := &pb.UserInfo{UserId: userID.String(), Email: "refresh.v2@v.com", Roles: []string{"p"}, IsActive: true}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(pbInfo, nil).Once()
	mockRepo.On("StoreRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()
	resp, err := svc.RefreshAccessToken(context.Background(), &pb.RefreshAccessTokenRequest{RefreshToken: rawOldRefreshToken})
	require.NoError(t, err); assert.NotEmpty(t, resp.AccessToken); assert.NotEqual(t, rawOldRefreshToken, resp.RefreshToken)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RefreshAccessToken_InvalidToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, "secret_refresh_invalid_v2", rlConfig) // GÜNCELLENDİ
	rawInvalidToken := "invalid-refresh-v2"; hashedInvalidToken := hashToken(rawInvalidToken)
	mockRepo.On("GetRefreshTokenByHash", mock.Anything, hashedInvalidToken).Return(nil, errors.New("not found")).Once()
	_, err := svc.RefreshAccessToken(context.Background(), &pb.RefreshAccessTokenRequest{RefreshToken: rawInvalidToken})
	st, _ := status.FromError(err); assert.Equal(t, codes.Unauthenticated, st.Code())
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Logout_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, "secret_logout_success_v2", rlConfig) // GÜNCELLENDİ
	rawRefreshToken := "logout_token_v2"; hashedRefreshToken := hashToken(rawRefreshToken)
	mockRepo.On("RevokeRefreshTokenByHash", mock.Anything, hashedRefreshToken).Return(nil).Once()
	resp, err := svc.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: rawRefreshToken})
	require.NoError(t, err); assert.Contains(t, resp.Message, "revoked")
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Logout_NoTokenProvided(t *testing.T) {
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(new(MockUserRepository), "secret_logout_notoken_v2", rlConfig) // GÜNCELLENDİ
	resp, err := svc.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: ""})
	require.NoError(t, err); assert.Contains(t, resp.Message, "No server-side refresh token")
}

func TestAuthServiceServer_RequestPasswordReset_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-reset-v2", rlConfig) // GÜNCELLENDİ
	email := "user.req.reset.v2@example.com"; userID := uuid.New()
	mockUserInfo := &pb.UserInfo{UserId: userID.String(), Email: email, IsActive: true}
	mockRepo.On("GetUserByEmail", mock.Anything, email).Return(mockUserInfo, "anyhash", true, nil).Once()
	mockRepo.On("StorePasswordResetToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()
	req := &pb.RequestPasswordResetRequest{Email: email}
	res, err := svc.RequestPasswordReset(context.Background(), req)
	require.NoError(t, err); assert.Contains(t, res.Message, "reset link has been sent"); assert.True(t, res.ExpiresInSeconds > 0)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RequestPasswordReset_UserNotFoundOrInactive(t *testing.T) {
	mockRepo := new(MockUserRepository)
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-reset-notfound-v2", rlConfig) // GÜNCELLENDİ
	email := "notfound.reset.v2@example.com"
	mockRepo.On("GetUserByEmail", mock.Anything, email).Return(nil, "", false, errors.New("user not found")).Once()
	req := &pb.RequestPasswordResetRequest{Email: email}
	res, err := svc.RequestPasswordReset(context.Background(), req)
	require.NoError(t, err); assert.Contains(t, res.Message, "reset link has been sent")
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ConfirmPasswordReset_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-confirm-v2", rlConfig) // GÜNCELLENDİ
	rawToken := "valid-raw-reset-token-v2"; hashedToken := hashToken(rawToken); userID := uuid.New(); newPassword := "NewSecureP@ss1v2"
	mockDbResetToken := &repository.PasswordResetToken{TokenHash: hashedToken, UserID: userID, ExpiresAt: time.Now().Add(10 * time.Minute), Consumed: false}
	mockRepo.On("GetValidPasswordResetTokenByHash", mock.Anything, hashedToken).Return(mockDbResetToken, nil).Once()
	mockRepo.On("UpdateUserPassword", mock.Anything, userID, mock.AnythingOfType("string")).Return(nil).Once()
	mockRepo.On("MarkPasswordResetTokenAsUsed", mock.Anything, hashedToken).Return(nil).Once()
	mockRepo.On("RevokeAllRefreshTokensForUser", mock.Anything, userID).Return(nil).Once()
	req := &pb.ConfirmPasswordResetRequest{ResetToken: rawToken, NewPassword: newPassword}
	res, err := svc.ConfirmPasswordReset(context.Background(), req)
	require.NoError(t, err); assert.Contains(t, res.Message, "Password successfully updated")
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ConfirmPasswordReset_InvalidToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	rlConfig := newTestRateLimiterConfig()
	svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-confirm-invalid-v2", rlConfig) // GÜNCELLENDİ
	rawToken := "invalid-or-expired-token-v2"; hashedToken := hashToken(rawToken); newPassword := "NewSecureP@ss1v2"
	mockRepo.On("GetValidPasswordResetTokenByHash", mock.Anything, hashedToken).Return(nil, errors.New("token not found, expired, or consumed")).Once()
	req := &pb.ConfirmPasswordResetRequest{ResetToken: rawToken, NewPassword: newPassword}
	res, err := svc.ConfirmPasswordReset(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res); st, _ := status.FromError(err); assert.Equal(t, codes.InvalidArgument, st.Code()); assert.Contains(t, st.Message(), "Invalid or expired reset token")
	mockRepo.AssertExpectations(t)
}

// --- E-posta Doğrulama RPC'leri İçin Unit Testler ---
func TestAuthServiceServer_RequestEmailVerification_Success(t *testing.T) {
	mockRepo := new(MockUserRepository);	testJWTSecret := "test_secret_email_verif_req_success_v2"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); userEmail := "unverified.user.req.v2@example.com"; userRoles := []string{"passenger"}
	accessClaims := jwt.MapClaims{ "sub": userID.String(), "email": userEmail, "roles": userRoles, "exp": time.Now().Add(time.Hour * 1).Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString()}
	accessTokenJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims);	signedAccessToken, errToken := accessTokenJwt.SignedString([]byte(testJWTSecret)); require.NoError(t, errToken)
	req := &pb.RequestEmailVerificationRequest{ AccessToken: signedAccessToken }
	mockValidatedUser := &pb.UserInfo{ UserId: userID.String(), Email: userEmail, FullName: "Unverified User To Verify V2", Roles: userRoles, IsActive: true, EmailVerified: false }
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockValidatedUser, nil).Once()
	mockRepo.On("StoreEmailVerificationToken", mock.Anything, userID, userEmail, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()
	res, err := authService.RequestEmailVerification(context.Background(), req)
	require.NoError(t, err); require.NotNil(t, res); assert.Contains(t, res.Message, "A verification link has been sent"); assert.True(t, res.ExpiresInSeconds > 0)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RequestEmailVerification_AlreadyVerified(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_email_already_verified_v2"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); userEmail := "already.verified.v2@example.com"
	accessClaims := jwt.MapClaims{"sub": userID.String(), "email": userEmail, "exp": time.Now().Add(time.Hour).Unix(), "jti": uuid.NewString()}; accessTokenJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims); signedAccessToken, _ := accessTokenJwt.SignedString([]byte(testJWTSecret))
	mockValidatedUser := &pb.UserInfo{UserId: userID.String(), Email: userEmail, IsActive: true, EmailVerified: true }
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockValidatedUser, nil).Once()
	req := &pb.RequestEmailVerificationRequest{AccessToken: signedAccessToken}
	res, err := authService.RequestEmailVerification(context.Background(), req)
	require.NoError(t, err); require.NotNil(t, res); assert.Equal(t, "Your email address is already verified.", res.Message)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ConfirmEmailVerification_Success(t *testing.T) {
	mockRepo := new(MockUserRepository); testJWTSecret := "test_secret_confirm_email_success_v2"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	rawToken := "raw_email_verification_token_confirm_v2"; hashedToken := hashToken(rawToken); userID := uuid.New(); userEmail := "confirm.this.email.v2@example.com"
	mockDbVerificationToken := &repository.EmailVerificationToken{ TokenHash: hashedToken, UserID: userID, Email: userEmail, ExpiresAt: time.Now().Add(time.Hour), Consumed:	false, }
	mockRepo.On("GetValidEmailVerificationTokenByHash", mock.Anything, hashedToken).Return(mockDbVerificationToken, nil).Once()
	mockRepo.On("MarkUserEmailAsVerified", mock.Anything, userID).Return(nil).Once()
	mockRepo.On("MarkEmailVerificationTokenAsUsed", mock.Anything, hashedToken).Return(nil).Once()
	expectedPbUserInfo := &pb.UserInfo{ UserId: userID.String(), Email: userEmail, FullName: "Email Verified User V2", Roles: []string{"passenger"}, IsActive: true, EmailVerified: true, }
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(expectedPbUserInfo, nil).Once()
	req := &pb.ConfirmEmailVerificationRequest{VerificationToken: rawToken}
	res, err := authService.ConfirmEmailVerification(context.Background(), req)
	require.NoError(t, err); require.NotNil(t, res); assert.Equal(t, "Email successfully verified.", res.Message)
	require.NotNil(t, res.User); assert.True(t, res.User.EmailVerified); assert.Equal(t, userID.String(), res.User.UserId)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ConfirmEmailVerification_InvalidToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_confirm_email_invalid_v3"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	rawToken := "invalid_or_expired_email_token_v3"; hashedToken := hashToken(rawToken)
	mockRepo.On("GetValidEmailVerificationTokenByHash", mock.Anything, hashedToken).Return(nil, fmt.Errorf("email verification token not found, expired, or consumed")).Once()
	req := &pb.ConfirmEmailVerificationRequest{VerificationToken: rawToken}
	res, err := authService.ConfirmEmailVerification(context.Background(), req)
	assert.Error(t, err, "ConfirmEmailVerification bir hata döndürmeliydi")
	assert.Nil(t, res, "Hata durumunda response (res) nil olmalıydı")
	st, ok := status.FromError(err); require.True(t, ok, "Hata gRPC status formatında olmalıydı")
	assert.Equal(t, codes.InvalidArgument, st.Code(), "gRPC hata kodu InvalidArgument olmalıydı")
	assert.Contains(t, st.Message(), "Invalid, expired, or already used verification token", "Hata mesajı bekleneni içermeliydi")
	mockRepo.AssertExpectations(t)
}

// --- ChangePassword RPC'si İçin Unit Testler ---
func TestAuthServiceServer_ChangePassword_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_for_change_password_v2" // Secret'ları testler arasında benzersiz yapmak iyi bir pratiktir
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); userEmail := "changepass.user.v2@example.com"; oldPassword := "OldSecurePassword123!"; newPassword := "NewSecurePassword456$"
	accessClaims := jwt.MapClaims{ "sub": userID.String(), "email": userEmail, "roles": []string{"passenger"}, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString(),	}
	accessTokenJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims);	signedAccessToken, _ := accessTokenJwt.SignedString([]byte(testJWTSecret))
	req := &pb.ChangePasswordRequest{	AccessToken: signedAccessToken,	OldPassword: oldPassword,	NewPassword: newPassword,}
	mockValidatedUser := &pb.UserInfo{UserId: userID.String(), Email: userEmail, IsActive: true}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockValidatedUser, nil).Once()
	hashedOldPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
	mockRepo.On("GetUserByEmail", mock.Anything, userEmail).Return(mockValidatedUser, string(hashedOldPassword), true, nil).Once()
	mockRepo.On("UpdateUserPassword", mock.Anything, userID, mock.AnythingOfType("string")).Return(nil).Once()
	mockRepo.On("RevokeAllRefreshTokensForUser", mock.Anything, userID).Return(nil).Once()
	res, err := authService.ChangePassword(context.Background(), req)
	require.NoError(t, err); require.NotNil(t, res); assert.Equal(t, "Password changed successfully.", res.Message)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ChangePassword_IncorrectOldPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_change_pass_wrong_old_v2"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); userEmail := "wrongoldpass.v2@example.com"
	accessClaims := jwt.MapClaims{"sub": userID.String(), "email": userEmail, "exp": time.Now().Add(time.Hour).Unix(), "jti": uuid.NewString()};	accessTokenJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims);	signedAccessToken, _ := accessTokenJwt.SignedString([]byte(testJWTSecret))
	req := &pb.ChangePasswordRequest{AccessToken: signedAccessToken, OldPassword: "wrong_old_password", NewPassword: "NewPassword123!"}
	mockValidatedUser := &pb.UserInfo{UserId: userID.String(), Email: userEmail, IsActive: true}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockValidatedUser, nil).Once()
	correctOldPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("correct_old_password"), bcrypt.DefaultCost)
	mockRepo.On("GetUserByEmail", mock.Anything, userEmail).Return(mockValidatedUser, string(correctOldPasswordHash), true, nil).Once()
	res, err := authService.ChangePassword(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res);	st, ok := status.FromError(err); require.True(t, ok);	assert.Equal(t, codes.Unauthenticated, st.Code()); assert.Contains(t, st.Message(), "Incorrect old password")
	mockRepo.AssertExpectations(t)
}

// --- UpdateUserMetadata RPC'si İçin Unit Testler ---
func TestAuthServiceServer_UpdateUserMetadata_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_update_metadata_success_v2"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	userID := uuid.New(); userEmail := "metadata.update.v2@example.com"; newFullName := "Updated User FullName V2"
	accessClaims := jwt.MapClaims{ "sub": userID.String(), "email": userEmail, "roles": []string{"passenger"}, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString(),	}
	accessTokenJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims);	signedAccessToken, _ := accessTokenJwt.SignedString([]byte(testJWTSecret))
	req := &pb.UpdateUserMetadataRequest{AccessToken: signedAccessToken, FullName: newFullName}
	mockValidatedUser := &pb.UserInfo{UserId: userID.String(), Email: userEmail, IsActive: true}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockValidatedUser, nil).Once()
	mockRepo.On("UpdateUserFullName", mock.Anything, userID, newFullName).Return(nil).Once()
	mockUpdatedUserInfo := &pb.UserInfo{ UserId: userID.String(), Email: userEmail, FullName: newFullName, Roles: []string{"passenger"}, IsActive: true, EmailVerified: false,	}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockUpdatedUserInfo, nil).Once()
	res, err := authService.UpdateUserMetadata(context.Background(), req)
	require.NoError(t, err); require.NotNil(t, res); require.NotNil(t, res.User); assert.Equal(t, userID.String(), res.User.UserId); assert.Equal(t, newFullName, res.User.FullName)
	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_UpdateUserMetadata_InvalidAccessToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_update_metadata_invalid_token_v2"
	rlConfig := newTestRateLimiterConfig()
	authService := NewAuthServiceServer(mockRepo, testJWTSecret, rlConfig) // GÜNCELLENDİ
	req := &pb.UpdateUserMetadataRequest{AccessToken: "invalid-or-expired-token", FullName: "Any Name"}
	res, err := authService.UpdateUserMetadata(context.Background(), req)
	assert.Error(t, err); assert.Nil(t, res); st, ok := status.FromError(err); require.True(t, ok); assert.Equal(t, codes.Unauthenticated, st.Code())
}

// hashToken yardımcı fonksiyonu (eğer servis paketinden import edilmiyorsa testlerde gerekebilir)
// func hashToken(token string) string {
// 	hasher := sha256.New()
// 	hasher.Write([]byte(token))
// 	return hex.EncodeToString(hasher.Sum(nil))
// }