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

// TODO: Login için yanlış şifre, kullanıcı yok, aktif olmayan kullanıcı senaryoları.
// TODO: ValidateToken için başarılı, geçersiz token, süresi dolmuş token, aktif olmayan kullanıcı senaryoları.
// TODO: RefreshAccessToken için başarılı, geçersiz refresh token, süresi dolmuş refresh token, kullanıcı yok/aktif değil senaryoları.
// TODO: Logout için test.