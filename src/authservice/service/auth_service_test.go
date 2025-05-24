package service

import (
	"context" // MockUserRepository'de repository.User.FullName için
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/src/authservice/genproto"
	"github.com/voyalis/voyago-base/src/authservice/repository"
)

// MockUserRepository, UserRepository interface'ini mock'lar.
type MockUserRepository struct {
	mock.Mock
}

var _ UserRepository = (*MockUserRepository)(nil) // Interface uyumluluğunu kontrol et

// --- MockUserRepository Metot Implementasyonları ---
func (m *MockUserRepository) CreateUser(ctx context.Context, email, passwordHash, fullName string) (*repository.User, error) {
	args := m.Called(ctx, email, passwordHash, fullName); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*repository.User), args.Error(1)
}
func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error) {
	args := m.Called(ctx, email); var ui *pb.UserInfo; if args.Get(0) != nil { ui = args.Get(0).(*pb.UserInfo) }; return ui, args.String(1), args.Bool(2), args.Error(3)
}
func (m *MockUserRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error) {
	args := m.Called(ctx, userID); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*pb.UserInfo), args.Error(1)
}
func (m *MockUserRepository) StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return m.Called(ctx, userID, tokenHash, expiresAt).Error(0)
}
func (m *MockUserRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	args := m.Called(ctx, tokenHash); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*repository.RefreshToken), args.Error(1)
}
func (m *MockUserRepository) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error {
	return m.Called(ctx, tokenHash).Error(0)
}
func (m *MockUserRepository) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	return m.Called(ctx, userID).Error(0)
}
func (m *MockUserRepository) UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error {
	return m.Called(ctx, userID).Error(0)
}
func (m *MockUserRepository) StorePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return m.Called(ctx, userID, tokenHash, expiresAt).Error(0)
}
func (m *MockUserRepository) GetValidPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*repository.PasswordResetToken, error) {
	args := m.Called(ctx, tokenHash); if args.Get(0) == nil { return nil, args.Error(1) }; return args.Get(0).(*repository.PasswordResetToken), args.Error(1)
}
func (m *MockUserRepository) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenHash string) error {
	return m.Called(ctx, tokenHash).Error(0)
}
func (m *MockUserRepository) UpdateUserPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	return m.Called(ctx, userID, newPasswordHash).Error(0)
}

// --- Test Fonksiyonları ---
// (TestAuthServiceServer_Register_Success, TestAuthService_Register_EmailAlreadyExists, TestAuthServiceServer_Login_Success,
// TestAuthServiceServer_Login_UserNotFound, TestAuthServiceServer_Login_IncorrectPassword, TestAuthServiceServer_Login_UserNotActive
// bir önceki mesajınızdaki gibi kalabilir veya "GPT"nin son örneklerindeki gibi güncellenebilir.)

// Örnek olarak Register ve Login testlerini bir önceki mesajınızdaki gibi bırakıyorum,
// şimdi ValidateToken ve sonrasını "GPT"nin verdiği gibi ekleyelim.

func TestAuthServiceServer_Register_Success(t *testing.T) { /* ... (önceki gibi) ... */ }
func TestAuthService_Register_EmailAlreadyExists(t *testing.T) { /* ... (önceki gibi) ... */ }
func TestAuthServiceServer_Login_Success(t *testing.T) { /* ... (önceki gibi) ... */ }
func TestAuthServiceServer_Login_UserNotFound(t *testing.T) { /* ... (önceki gibi) ... */ }
func TestAuthServiceServer_Login_IncorrectPassword(t *testing.T) { /* ... (önceki gibi) ... */ }
func TestAuthServiceServer_Login_UserNotActive(t *testing.T) { /* ... (önceki gibi) ... */ }


// --- ValidateToken Testleri ("GPT"den) ---
func TestAuthServiceServer_ValidateToken_Success(t *testing.T) {
    mockRepo := new(MockUserRepository)
    secret := "secret123_validate_success"
    svc := NewAuthServiceServer(mockRepo, secret)

    userID := uuid.New()
    userEmail := "e.validate@x.com"
    userRoles := []string{"passenger"}
    claims := jwt.MapClaims{ "sub": userID.String(), "email": userEmail, "roles": userRoles, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString() }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signed, _ := token.SignedString([]byte(secret))

    pbInfo := &pb.UserInfo{UserId: userID.String(), Email: userEmail, IsActive: true, Roles: userRoles, FullName: "Validate Success User", EmailVerified: true}
    mockRepo.On("GetUserByID", mock.Anything, userID).Return(pbInfo, nil).Once()

    resp, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: signed})
    require.NoError(t, err)
    assert.Equal(t, userID.String(), resp.User.UserId)
    mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ValidateToken_InvalidSignature(t *testing.T) {
    svc := NewAuthServiceServer(new(MockUserRepository), "actual_secret_key_validate")
    claims := jwt.MapClaims{"sub": "user123_inv_sig", "exp": time.Now().Add(time.Hour).Unix()}
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedWithWrongSecret, _ := token.SignedString([]byte("wrong_secret_key_for_sig"))
    _, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: signedWithWrongSecret})
    st, _ := status.FromError(err)
    assert.Equal(t, codes.Unauthenticated, st.Code())
    assert.Contains(t, st.Message(), "Invalid access token") // Genel hata mesajımız
}

func TestAuthServiceServer_ValidateToken_Expired(t *testing.T) {
    svc := NewAuthServiceServer(new(MockUserRepository), "secret_expired_validate")
    claims := jwt.MapClaims{"sub": "user_exp_validate", "email": "exp@v.com", "roles": []string{"p"}, "exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(), "jti": uuid.NewString()}
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    signedExpiredToken, _ := token.SignedString([]byte("secret_expired_validate"))
    _, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: signedExpiredToken})
    st, _ := status.FromError(err)
    assert.Equal(t, codes.Unauthenticated, st.Code())
	// ValidateToken fonksiyonumuzda errors.Is(err, jwt.ErrTokenExpired) kontrolü eklediğimizi varsayıyoruz.
    assert.Contains(t, st.Message(), "token is expired")
}

func TestAuthServiceServer_ValidateToken_UserInactive(t *testing.T) {
    mockRepo := new(MockUserRepository); secret := "secret_inactive_validate"; svc := NewAuthServiceServer(mockRepo, secret)
    userID := uuid.New()
    claims := jwt.MapClaims{"sub": userID.String(), "email": "inactive.val@v.com", "exp": time.Now().Add(time.Hour).Unix(), "jti": uuid.NewString()}
    tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
    mockRepo.On("GetUserByID", mock.Anything, userID).Return(&pb.UserInfo{UserId: userID.String(), IsActive: false}, nil).Once()
    _, err := svc.ValidateToken(context.Background(), &pb.ValidateTokenRequest{Token: tok})
    st, _ := status.FromError(err); assert.Equal(t, codes.PermissionDenied, st.Code()); assert.Contains(t, st.Message(), "User account is disabled")
    mockRepo.AssertExpectations(t)
}

// --- RefreshAccessToken Testleri ("GPT"den) ---
func TestAuthServiceServer_RefreshAccessToken_Success(t *testing.T) {
    mockRepo := new(MockUserRepository); secret := "secret_refresh_success"; svc := NewAuthServiceServer(mockRepo, secret)
    userID := uuid.New(); rawOldRefreshToken := uuid.NewString(); hashedOldRefreshToken := hashToken(rawOldRefreshToken) // hashToken servis içinde tanımlı olmalı
    dbToken := &repository.RefreshToken{UserID: userID, TokenHash: hashedOldRefreshToken, ExpiresAt: time.Now().Add(time.Hour)}
    mockRepo.On("GetRefreshTokenByHash", mock.Anything, hashedOldRefreshToken).Return(dbToken, nil).Once()
    mockRepo.On("RevokeRefreshTokenByHash", mock.Anything, hashedOldRefreshToken).Return(nil).Once()
    pbInfo := &pb.UserInfo{UserId: userID.String(), Email: "refresh@v.com", Roles: []string{"p"}, IsActive: true}
    mockRepo.On("GetUserByID", mock.Anything, userID).Return(pbInfo, nil).Once()
    mockRepo.On("StoreRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()
    resp, err := svc.RefreshAccessToken(context.Background(), &pb.RefreshAccessTokenRequest{RefreshToken: rawOldRefreshToken})
    require.NoError(t, err); assert.NotEmpty(t, resp.AccessToken); assert.NotEqual(t, rawOldRefreshToken, resp.RefreshToken)
    mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RefreshAccessToken_InvalidToken(t *testing.T) {
    mockRepo := new(MockUserRepository); svc := NewAuthServiceServer(mockRepo, "secret_refresh_invalid")
    rawInvalidToken := "invalid-refresh"; hashedInvalidToken := hashToken(rawInvalidToken)
    mockRepo.On("GetRefreshTokenByHash", mock.Anything, hashedInvalidToken).Return(nil, errors.New("not found")).Once()
    _, err := svc.RefreshAccessToken(context.Background(), &pb.RefreshAccessTokenRequest{RefreshToken: rawInvalidToken})
    st, _ := status.FromError(err); assert.Equal(t, codes.Unauthenticated, st.Code())
    mockRepo.AssertExpectations(t)
}

// --- Logout Testleri ("GPT"den) ---
func TestAuthServiceServer_Logout_Success(t *testing.T) {
    mockRepo := new(MockUserRepository); svc := NewAuthServiceServer(mockRepo, "secret_logout_success")
    rawRefreshToken := "logout_token"; hashedRefreshToken := hashToken(rawRefreshToken)
    mockRepo.On("RevokeRefreshTokenByHash", mock.Anything, hashedRefreshToken).Return(nil).Once()
    resp, err := svc.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: rawRefreshToken})
    require.NoError(t, err); assert.Contains(t, resp.Message, "revoked")
    mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Logout_NoTokenProvided(t *testing.T) {
    svc := NewAuthServiceServer(new(MockUserRepository), "secret_logout_notoken") // mockRepo'ya gerek yok
    resp, err := svc.Logout(context.Background(), &pb.LogoutRequest{RefreshToken: ""})
    require.NoError(t, err); assert.Contains(t, resp.Message, "No server-side refresh token")
    // new(MockUserRepository).AssertExpectations(t) // Bu satır mockRepo kullanılmadığı için gereksiz veya hata verebilir.
}

// --- Şifre Sıfırlama Akışı Testleri ("GPT"den uyarlanmış) ---
func TestAuthServiceServer_RequestPasswordReset_Success(t *testing.T) {
    mockRepo := new(MockUserRepository)
    svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-reset")
    email := "user.req.reset@example.com"
    userID := uuid.New()

    mockUserInfo := &pb.UserInfo{UserId: userID.String(), Email: email, IsActive: true}
    mockRepo.On("GetUserByEmail", mock.Anything, email).Return(mockUserInfo, "anyhash", true, nil).Once()
    mockRepo.On("StorePasswordResetToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()

    req := &pb.RequestPasswordResetRequest{Email: email}
    res, err := svc.RequestPasswordReset(context.Background(), req)

    require.NoError(t, err)
    assert.Contains(t, res.Message, "reset link has been sent")
    assert.True(t, res.ExpiresInSeconds > 0)
    mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RequestPasswordReset_UserNotFoundOrInactive(t *testing.T) {
    mockRepo := new(MockUserRepository)
    svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-reset-notfound")
    email := "notfound.reset@example.com"

    // Kullanıcı bulunamadı durumu
    mockRepo.On("GetUserByEmail", mock.Anything, email).Return(nil, "", false, errors.New("user not found")).Once()

    req := &pb.RequestPasswordResetRequest{Email: email}
    res, err := svc.RequestPasswordReset(context.Background(), req)
    require.NoError(t, err) // Güvenlik nedeniyle hata dönmüyoruz
    assert.Contains(t, res.Message, "reset link has been sent") // Genel mesaj
    mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ConfirmPasswordReset_Success(t *testing.T) {
    mockRepo := new(MockUserRepository)
    svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-confirm")

    rawToken := "valid-raw-reset-token-123"
    hashedToken := hashToken(rawToken) // service'deki hashToken fonksiyonunu kullanıyoruz
    userID := uuid.New()
    newPassword := "NewSecureP@ss1"

    mockDbResetToken := &repository.PasswordResetToken{
        TokenHash: hashedToken,
        UserID:    userID,
        ExpiresAt: time.Now().Add(10 * time.Minute),
        Consumed:  false,
    }
    mockRepo.On("GetValidPasswordResetTokenByHash", mock.Anything, hashedToken).Return(mockDbResetToken, nil).Once()
    mockRepo.On("UpdateUserPassword", mock.Anything, userID, mock.AnythingOfType("string")).Return(nil).Once()
    mockRepo.On("MarkPasswordResetTokenAsUsed", mock.Anything, hashedToken).Return(nil).Once()
    mockRepo.On("RevokeAllRefreshTokensForUser", mock.Anything, userID).Return(nil).Once()

    req := &pb.ConfirmPasswordResetRequest{ResetToken: rawToken, NewPassword: newPassword}
    res, err := svc.ConfirmPasswordReset(context.Background(), req)

    require.NoError(t, err)
    assert.Contains(t, res.Message, "Password successfully updated")
    mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ConfirmPasswordReset_InvalidToken(t *testing.T) {
    mockRepo := new(MockUserRepository)
    svc := NewAuthServiceServer(mockRepo, "test-secret-pwd-confirm-invalid")
    rawToken := "invalid-or-expired-token"
    hashedToken := hashToken(rawToken)
    newPassword := "NewSecureP@ss1"

    mockRepo.On("GetValidPasswordResetTokenByHash", mock.Anything, hashedToken).
        Return(nil, errors.New("token not found, expired, or consumed")).Once()

    req := &pb.ConfirmPasswordResetRequest{ResetToken: rawToken, NewPassword: newPassword}
    res, err := svc.ConfirmPasswordReset(context.Background(), req)

    assert.Error(t, err)
    assert.Nil(t, res)
    st, _ := status.FromError(err)
    assert.Equal(t, codes.InvalidArgument, st.Code()) // Veya Unauthenticated, servis mantığına göre
    assert.Contains(t, st.Message(), "Invalid or expired reset token")
    mockRepo.AssertExpectations(t)
}

// TODO: ChangePassword, RequestEmailVerification, ConfirmEmailVerification, UpdateUserMetadata için unit testler.