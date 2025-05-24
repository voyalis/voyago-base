package service

import (
	"context"
	"database/sql" // repository.User.FullName için
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/src/authservice/genproto"
	"github.com/voyalis/voyago-base/src/authservice/repository"
)

// MockUserRepository, UserRepository interface'ini mock'lar.
type MockUserRepository struct {
	mock.Mock
}

// Bu satır, MockUserRepository'nin gerçekten UserRepository interface'ini
// implemente edip etmediğini derleme zamanında kontrol eder.
var _ UserRepository = (*MockUserRepository)(nil)

// --- MockUserRepository Metot Implementasyonları ---
func (m *MockUserRepository) CreateUser(ctx context.Context, email, passwordHash, fullName string) (*repository.User, error) {
	args := m.Called(ctx, email, passwordHash, fullName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.User), args.Error(1)
}
func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error) {
	args := m.Called(ctx, email)
	var userInfo *pb.UserInfo
	if args.Get(0) != nil {
		userInfo = args.Get(0).(*pb.UserInfo)
	}
	return userInfo, args.String(1), args.Bool(2), args.Error(3)
}
func (m *MockUserRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.UserInfo), args.Error(1)
}
func (m *MockUserRepository) StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}
func (m *MockUserRepository) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.RefreshToken), args.Error(1)
}
func (m *MockUserRepository) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}
func (m *MockUserRepository) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// --- Test Fonksiyonları ---
func TestAuthServiceServer_Register_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test-jwt-secret-for-authservice"
	authService := NewAuthServiceServer(mockRepo, testJWTSecret)

	req := &pb.RegisterRequest{
		Email:    "newuser.service@example.com",
		Password: "SecurePassword123$",
		FullName: "Service Test User",
	}

	mockedRepoUserID := uuid.New()
	mockedRepoUser := &repository.User{ // Bu, repo.CreateUser'dan dönecek
		ID:            mockedRepoUserID,
		Email:         req.Email,
		PasswordHash:  "mocked_hash_from_repo", // Gerçek hash değil, sadece struct için
		FullName:      sql.NullString{String: req.FullName, Valid: true},
		IsActive:      true,
		EmailVerified: false, // Varsayılan
	}
	// Servis katmanı, CreateUser'a hashlenmiş şifreyi gönderir.
	// mock.AnythingOfType("string") ile hashlenmiş şifreyi eşleştiriyoruz.
	mockRepo.On("CreateUser", mock.Anything, req.Email, mock.AnythingOfType("string"), req.FullName).
		Return(mockedRepoUser, nil).Once()

	// Servis katmanı, CreateUser'dan sonra GetUserByID'yi çağırır.
	expectedPbUserInfo := &pb.UserInfo{
		UserId:        mockedRepoUserID.String(),
		Email:         req.Email,
		FullName:      req.FullName,
		Roles:         []string{"passenger"}, // GetUserByID'nin bu rolleri getirdiğini varsayıyoruz
		IsActive:      true,
		EmailVerified: false,
	}
	mockRepo.On("GetUserByID", mock.Anything, mockedRepoUserID).Return(expectedPbUserInfo, nil).Once()

	res, err := authService.Register(context.Background(), req)

	assert.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.User)
	assert.Equal(t, expectedPbUserInfo.UserId, res.User.UserId)
	assert.Equal(t, req.Email, res.User.Email)
	assert.Contains(t, res.User.Roles, "passenger")
	assert.True(t, res.User.IsActive)
	assert.Equal(t, "User registered successfully", res.Message)

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_EmailAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_key"
	authService := NewAuthServiceServer(mockRepo, testJWTSecret)

	req := &pb.RegisterRequest{
		Email:    "exists.service@example.com",
		Password: "password123",
		FullName: "Existing Service User",
	}

	mockRepo.On("CreateUser", mock.Anything, req.Email, mock.AnythingOfType("string"), req.FullName).
		Return(nil, fmt.Errorf("email '%s' already exists", req.Email)).Once()

	res, err := authService.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, res)
	st, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status error")
	assert.Equal(t, codes.AlreadyExists, st.Code())
	assert.Contains(t, st.Message(), "already exists")

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_key_for_login_123"
	authService := NewAuthServiceServer(mockRepo, testJWTSecret)

	req := &pb.LoginRequest{
		Email:    "logincandidate@example.com",
		Password: "ValidPassword123$",
	}

	mockUserID := uuid.New()
	mockPbUserInfoFromDB := &pb.UserInfo{ // GetUserByEmail'den dönecek mock UserInfo
		UserId:        mockUserID.String(),
		Email:         req.Email,
		FullName:      "Login Test User",
		Roles:         []string{"passenger"},
		IsActive:      true,
		EmailVerified: true,
	}
	hashedRealPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	mockPasswordHash := string(hashedRealPassword)

	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).
		Return(mockPbUserInfoFromDB, mockPasswordHash, true, nil).Once()
	
	mockRepo.On("StoreRefreshToken", mock.Anything, mockUserID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).
		Return(nil).Once()
	mockRepo.On("UpdateUserLastSignInAt", mock.Anything, mockUserID).
		Return(nil).Once()

	res, err := authService.Login(context.Background(), req)

	assert.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.User)
	assert.Equal(t, mockPbUserInfoFromDB.UserId, res.User.UserId)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	assert.True(t, res.ExpiresIn > 0 && res.ExpiresIn <= 3600*1) // 1 saat access token ömrü

	// Access Token'ı decode edip claim'leri kontrol et
	token, jwtErr := jwt.Parse(res.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(testJWTSecret), nil
	})
	assert.NoError(t, jwtErr)
	assert.True(t, token.Valid)
	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, mockPbUserInfoFromDB.UserId, claims["sub"])
	assert.Equal(t, mockPbUserInfoFromDB.Email, claims["email"])
	// Roller için type assertion
	if rolesClaim, rolesOk := claims["roles"].([]interface{}); rolesOk {
		var rolesStr []string
		for _, r := range rolesClaim {
			if str, strOk := r.(string); strOk {
				rolesStr = append(rolesStr, str)
			}
		}
		assert.ElementsMatch(t, mockPbUserInfoFromDB.Roles, rolesStr)
	} else {
		t.Errorf("Roles claim is not of expected type []interface{} or is missing")
	}
	mockRepo.AssertExpectations(t)
}
// ... (mevcut importlar ve MockUserRepository aynı kalır) ...

func TestAuthServiceServer_Login_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_for_login_notfound"
	authService := NewAuthServiceServer(mockRepo, testJWTSecret)

	req := &pb.LoginRequest{
		Email:    "notfound.service@example.com",
		Password: "AnyPassword123!",
	}

	// Repository.GetUserByEmail çağrısında "user not found" hatası mock'la
	// (sql.ErrNoRows'a karşılık gelen bir fmt.Errorf mesajı)
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).
		Return(nil, "", false, fmt.Errorf("user with email '%s' not found", req.Email)).Once()
		// StoreRefreshToken ve UpdateUserLastSignInAt bu senaryoda çağrılmamalı

	res, err := authService.Login(context.Background(), req)

	assert.Error(t, err, "Hata dönmeliydi")
	assert.Nil(t, res, "Yanıt nil olmalıydı")

	st, ok := status.FromError(err)
	require.True(t, ok, "Hata gRPC status formatında olmalıydı")
	assert.Equal(t, codes.Unauthenticated, st.Code(), "gRPC hata kodu Unauthenticated olmalıydı")
	assert.Contains(t, st.Message(), "Invalid email or password", "Hata mesajı bekleneni içermeliydi")

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_IncorrectPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_for_login_wrongpass"
	authService := NewAuthServiceServer(mockRepo, testJWTSecret)

	req := &pb.LoginRequest{
		Email:    "user.wrongpass@example.com",
		Password: "IncorrectPassword123!",
	}

	mockUserID := uuid.New()
	mockPbUserInfoFromDB := &pb.UserInfo{
		UserId:        mockUserID.String(),
		Email:         req.Email,
		FullName:      "User With Wrong Pass",
		Roles:         []string{"passenger"},
		IsActive:      true,
		EmailVerified: true,
	}
	// Gerçek şifre "CorrectPassword123!" olsun, ama biz "IncorrectPassword123!" ile deniyoruz
	hashedCorrectPassword, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword123!"), bcrypt.DefaultCost)

	// Repository.GetUserByEmail başarılı dönsün, ama hash farklı olacak
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).
		Return(mockPbUserInfoFromDB, string(hashedCorrectPassword), true, nil).Once()
		// StoreRefreshToken ve UpdateUserLastSignInAt bu senaryoda çağrılmamalı

	res, err := authService.Login(context.Background(), req)

	assert.Error(t, err, "Hata dönmeliydi")
	assert.Nil(t, res, "Yanıt nil olmalıydı")

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid email or password")

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Login_UserNotActive(t *testing.T) {
	mockRepo := new(MockUserRepository)
	testJWTSecret := "test_secret_for_login_inactive"
	authService := NewAuthServiceServer(mockRepo, testJWTSecret)

	req := &pb.LoginRequest{
		Email:    "inactive.user@example.com",
		Password: "ValidPassword123!",
	}

	mockUserID := uuid.New()
	mockPbUserInfoFromDB := &pb.UserInfo{
		UserId:        mockUserID.String(),
		Email:         req.Email,
		FullName:      "Inactive User",
		Roles:         []string{"passenger"},
		IsActive:      false, // Kullanıcı aktif değil
		EmailVerified: true,
	}
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	// Repository.GetUserByEmail, kullanıcıyı bulsun ama isActive false dönsün
	mockRepo.On("GetUserByEmail", mock.Anything, req.Email).
		Return(mockPbUserInfoFromDB, string(hashedPassword), false, nil).Once()

	res, err := authService.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, res)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code()) // Veya Unauthenticated, servis mantığına göre
	assert.Contains(t, st.Message(), "User account is disabled")

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ValidateToken_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	secretKey := "my_super_secret_key_for_validation"
	authService := NewAuthServiceServer(mockRepo, secretKey)

	userID := uuid.New()
	userEmail := "validate.success@example.com"
	userRoles := []string{"passenger", "editor"}

	// Geçerli bir access token oluşturalım
	accessClaims := jwt.MapClaims{
		"sub":   userID.String(),
		"email": userEmail,
		"roles": userRoles,
		"exp":   time.Now().Add(time.Hour * 1).Unix(), // 1 saat geçerli
		"iat":   time.Now().Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString([]byte(secretKey))
	require.NoError(t, err)

	// GetUserByID çağrısını mock'la
	expectedPbUserInfo := &pb.UserInfo{
		UserId:        userID.String(),
		Email:         userEmail,
		FullName:      "Validated User",
		Roles:         userRoles,
		IsActive:      true,
		EmailVerified: true,
	}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(expectedPbUserInfo, nil).Once()

	req := &pb.ValidateTokenRequest{Token: signedAccessToken}
	res, err := authService.ValidateToken(context.Background(), req)

	assert.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.User)
	assert.Equal(t, expectedPbUserInfo.UserId, res.User.UserId)
	assert.Equal(t, expectedPbUserInfo.Email, res.User.Email)
	assert.ElementsMatch(t, expectedPbUserInfo.Roles, res.User.Roles)
	assert.True(t, res.User.IsActive)

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_ValidateToken_InvalidSignature(t *testing.T) {
	mockRepo := new(MockUserRepository) // Bu testte repo çağrılmayacak ama constructor bekliyor
	authService := NewAuthServiceServer(mockRepo, "actual_secret_key")

	// Başka bir secret ile imzalanmış token
	claims := jwt.MapClaims{"sub": "user123", "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedWithWrongSecret, _ := token.SignedString([]byte("wrong_secret_key"))

	req := &pb.ValidateTokenRequest{Token: signedWithWrongSecret}
	res, err := authService.ValidateToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, res)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid or expired access token") // jwt.Parse hatası bu mesajı tetikler
}

func TestAuthServiceServer_ValidateToken_Expired(t *testing.T) {
	mockRepo := new(MockUserRepository)
	secretKey := "secret_for_expired_token_test"
	authService := NewAuthServiceServer(mockRepo, secretKey)

	claims := jwt.MapClaims{
		"sub":   uuid.NewString(),
		"email": "expired@example.com",
		"roles": []string{"passenger"},
		"exp":   time.Now().Add(-time.Hour * 1).Unix(), // 1 SAAT ÖNCE EXPIRE OLMUŞ
		"iat":   time.Now().Add(-time.Hour * 2).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedExpiredToken, _ := token.SignedString([]byte(secretKey))

	req := &pb.ValidateTokenRequest{Token: signedExpiredToken}
	res, err := authService.ValidateToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, res)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid or expired access token") // jwt.Parse bu hatayı verir
}

func TestAuthServiceServer_ValidateToken_UserNotActive(t *testing.T) {
	mockRepo := new(MockUserRepository)
	secretKey := "secret_for_inactive_user_test"
	authService := NewAuthServiceServer(mockRepo, secretKey)

	userID := uuid.New()
	claims := jwt.MapClaims{
		"sub":   userID.String(),
		"email": "inactive.validate@example.com",
		"roles": []string{"passenger"},
		"exp":   time.Now().Add(time.Hour * 1).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte(secretKey))

	// GetUserByID çağrısında IsActive=false dönsün
	mockRepo.On("GetUserByID", mock.Anything, userID).
		Return(&pb.UserInfo{UserId: userID.String(), Email: "inactive.validate@example.com", IsActive: false}, nil).Once()

	req := &pb.ValidateTokenRequest{Token: signedToken}
	res, err := authService.ValidateToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, res)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "User account is disabled")

	mockRepo.AssertExpectations(t)
}


// --- RefreshAccessToken Testleri ---
func TestAuthServiceServer_RefreshAccessToken_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	secretKey := "my_refresh_secret_123"
	authService := NewAuthServiceServer(mockRepo, secretKey)

	userID := uuid.New()
	rawOldRefreshToken := uuid.NewString() // Client'tan gelen ham refresh token
	hashedOldRefreshToken := hashRefreshToken(rawOldRefreshToken)

	// Repo.GetRefreshTokenByHash çağrısını mock'la
	mockDbRefreshToken := &repository.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hashedOldRefreshToken,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7), // Daha geçerli
		Revoked:   false,
	}
	mockRepo.On("GetRefreshTokenByHash", mock.Anything, hashedOldRefreshToken).Return(mockDbRefreshToken, nil).Once()

	// Repo.RevokeRefreshTokenByHash çağrısını mock'la
	mockRepo.On("RevokeRefreshTokenByHash", mock.Anything, hashedOldRefreshToken).Return(nil).Once()

	// Repo.GetUserByID çağrısını mock'la
	mockPbUserInfo := &pb.UserInfo{
		UserId:        userID.String(),
		Email:         "refreshed.user@example.com",
		FullName:      "Refreshed User",
		Roles:         []string{"premium_passenger"},
		IsActive:      true,
		EmailVerified: true,
	}
	mockRepo.On("GetUserByID", mock.Anything, userID).Return(mockPbUserInfo, nil).Once()

	// Repo.StoreRefreshToken çağrısını mock'la (yeni refresh token için)
	mockRepo.On("StoreRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()

	req := &pb.RefreshAccessTokenRequest{RefreshToken: rawOldRefreshToken}
	res, err := authService.RefreshAccessToken(context.Background(), req)

	assert.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.User)
	assert.Equal(t, userID.String(), res.User.UserId)
	assert.NotEmpty(t, res.AccessToken)
	assert.NotEmpty(t, res.RefreshToken)
	assert.NotEqual(t, rawOldRefreshToken, res.RefreshToken, "Yeni refresh token üretilmeli")
	assert.True(t, res.ExpiresIn > 0)

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_RefreshAccessToken_InvalidOrExpired(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := NewAuthServiceServer(mockRepo, "test_secret")

	rawInvalidRefreshToken := "invalid-refresh-token-string"
	hashedInvalidRefreshToken := hashRefreshToken(rawInvalidRefreshToken)

	mockRepo.On("GetRefreshTokenByHash", mock.Anything, hashedInvalidRefreshToken).
		Return(nil, fmt.Errorf("refresh token not found, expired, or revoked")).Once()

	req := &pb.RefreshAccessTokenRequest{RefreshToken: rawInvalidRefreshToken}
	res, err := authService.RefreshAccessToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, res)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid or expired refresh token")

	mockRepo.AssertExpectations(t)
}

// --- Logout Testleri ---
func TestAuthServiceServer_Logout_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	authService := NewAuthServiceServer(mockRepo, "test_secret_logout")

	rawRefreshToken := "token_for_logout"
	hashedRefreshToken := hashRefreshToken(rawRefreshToken)

	mockRepo.On("RevokeRefreshTokenByHash", mock.Anything, hashedRefreshToken).Return(nil).Once()

	req := &pb.LogoutRequest{RefreshToken: rawRefreshToken}
	res, err := authService.Logout(context.Background(), req)

	assert.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "Successfully logged out and refresh token revoked.", res.Message)

	mockRepo.AssertExpectations(t)
}

func TestAuthServiceServer_Logout_NoTokenProvided(t *testing.T) {
	mockRepo := new(MockUserRepository) // Bu testte repo çağrılmayacak
	authService := NewAuthServiceServer(mockRepo, "test_secret_logout_no_token")

	req := &pb.LogoutRequest{RefreshToken: ""} // Boş refresh token
	res, err := authService.Logout(context.Background(), req)

	assert.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "Logged out. No server-side refresh token to revoke.", res.Message)

	mockRepo.AssertExpectations(t) // Hiçbir repo metodu çağrılmadığı için bu da geçerli olmalı
}


// TODO: Diğer RPC'ler için (ChangePassword, RequestPasswordReset vb.) unit testler eklenecek.