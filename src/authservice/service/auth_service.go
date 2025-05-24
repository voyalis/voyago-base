package service

import (
	"context"
	"crypto/rand"     // Güvenli rastgele byte üretimi için
	"crypto/sha256"   // repository.User.FullName için ve hatalar için
	"encoding/base64" // Token'ı string'e çevirmek için
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/src/authservice/genproto"
	"github.com/voyalis/voyago-base/src/authservice/repository"
)

const (
	passwordResetTokenBytesLength = 32             // Token için byte uzunluğu (256-bit)
	passwordResetTokenExpiry      = 15 * time.Minute // Token geçerlilik süresi
	// maxActivePasswordResetTokens = 3 // Kullanıcı başına aktif sıfırlama token sayısı limiti (opsiyonel)
	emailVerificationTokenBytesLength = 32             // YENİ
	emailVerificationTokenExpiry      = 24 * time.Hour // YENİ (örn: 24 saat)
)

// UserRepository interface'i, AuthService'in repository'ye olan bağımlılığını tanımlar.
type UserRepository interface {
	CreateUser(ctx context.Context, email, passwordHash, fullName string) (*repository.User, error)
	GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string /*passwordHash*/, bool /*isActive*/, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error)
	StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error)
	RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error
	UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error
	StorePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	GetValidPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*repository.PasswordResetToken, error)
	MarkPasswordResetTokenAsUsed(ctx context.Context, tokenHash string) error
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error
	StoreEmailVerificationToken(ctx context.Context, userID uuid.UUID, email string, tokenHash string, expiresAt time.Time) error
	GetValidEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*repository.EmailVerificationToken, error) // repository.EmailVerificationToken DÖNÜYOR
	MarkEmailVerificationTokenAsUsed(ctx context.Context, tokenHash string) error
	MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error
}

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	userRepo  UserRepository
	jwtSecret []byte
}

func NewAuthServiceServer(repo UserRepository, secretKeyVal string) *AuthServiceServer {
	if secretKeyVal == "" {
		slog.Error("JWT_SECRET_KEY must be set and passed to NewAuthServiceServer. Application will panic.")
		panic("JWT_SECRET_KEY is empty in NewAuthServiceServer")
	}
	return &AuthServiceServer{
		userRepo:  repo,
		jwtSecret: []byte(secretKeyVal),
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func hashToken(token string) string { // Genel bir token hash fonksiyonu
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}

func generateSecureRandomToken(length int) (string, error) {
    tokenBytes := make([]byte, length)
    if _, err := rand.Read(tokenBytes); err != nil {
        slog.Error("Failed to generate random bytes for token", "error", err)
        return "", fmt.Errorf("failed to generate secure token: %w", err)
    }
    return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	slog.InfoContext(ctx, "Service: Register request received", "email", req.Email, "fullName", req.FullName)
	if req.Email == "" || req.Password == "" {
		slog.WarnContext(ctx, "Service: Register failed - missing email or password", "email", req.Email)
		return nil, status.Errorf(codes.InvalidArgument, "Email and password are required")
	}
	if len(req.Password) < 8 { // Temel şifre politikası
		slog.WarnContext(ctx, "Service: Register failed - password too short", "email", req.Email)
		return nil, status.Errorf(codes.InvalidArgument, "Password must be at least 8 characters long")
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Error hashing password", "email", req.Email, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to process password")
	}

	createdRepoUser, err := s.userRepo.CreateUser(ctx, req.Email, hashedPassword, req.FullName)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			slog.WarnContext(ctx, "Service: User registration conflict - email already exists", "email", req.Email, "error", err.Error())
			return nil, status.Errorf(codes.AlreadyExists, err.Error())
		}
		slog.ErrorContext(ctx, "Service: User creation failed in repository", "email", req.Email, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to register user")
	}

	userInfo, err := s.userRepo.GetUserByID(ctx, createdRepoUser.ID)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Registered user but failed to fetch details for response", "userID", createdRepoUser.ID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "User registered but failed to retrieve details")
	}

	slog.InfoContext(ctx, "Service: User registered successfully", "userID", userInfo.UserId, "email", userInfo.Email)
	return &pb.RegisterResponse{User: userInfo, Message: "User registered successfully"}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	slog.InfoContext(ctx, "Service: Login attempt started", "email", req.Email)
	if req.Email == "" || req.Password == "" {
		slog.WarnContext(ctx, "Service: Login failed - missing email or password", "email", req.Email)
		return nil, status.Errorf(codes.InvalidArgument, "Email and password are required")
	}

	userInfo, storedPasswordHash, isActive, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		slog.WarnContext(ctx, "Service: Login failed - GetUserByEmail", "email", req.Email, "error", err.Error())
		return nil, status.Errorf(codes.Unauthenticated, "Invalid email or password")
	}
	if !isActive {
		slog.WarnContext(ctx, "Service: Login blocked - inactive account", "userID", userInfo.UserId, "email", req.Email)
		return nil, status.Errorf(codes.PermissionDenied, "User account is disabled")
	}
	if !checkPasswordHash(req.Password, storedPasswordHash) {
		slog.WarnContext(ctx, "Service: Login failed - incorrect password", "userID", userInfo.UserId, "email", req.Email)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid email or password")
	}

	accessTokenExp := time.Now().Add(time.Hour * 1) // Access token 1 saat geçerli
	accessClaims := jwt.MapClaims{
		"sub":   userInfo.UserId, "email": userInfo.Email, "roles": userInfo.Roles,
		"exp": accessTokenExp.Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(s.jwtSecret)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Error signing access token", "userID", userInfo.UserId, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Could not generate access token")
	}

	rawRefreshToken, err := generateSecureRandomToken(32) // 32 byte -> 43 char base64
	if err != nil {
		slog.ErrorContext(ctx, "Service: Error generating raw refresh token", "userID", userInfo.UserId, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Could not generate refresh token")
	}
	hashedRefreshToken := hashToken(rawRefreshToken) // Refresh token'ı hash'le
	refreshTokenExp := time.Now().Add(time.Hour * 24 * 30) // Refresh token 30 gün geçerli
	parsedUserID, _ := uuid.Parse(userInfo.UserId)

	if err := s.userRepo.StoreRefreshToken(ctx, parsedUserID, hashedRefreshToken, refreshTokenExp); err != nil {
		slog.ErrorContext(ctx, "Service: Failed to store refresh token", "userID", userInfo.UserId, "error", err.Error())
		// Bu hata login işlemini engellemeli mi? Genellikle evet.
		return nil, status.Errorf(codes.Internal, "Could not complete login process (token storage)")
	}
	if err := s.userRepo.UpdateUserLastSignInAt(ctx, parsedUserID); err != nil {
		slog.WarnContext(ctx, "Service: Failed to update last_sign_in_at", "userID", userInfo.UserId, "error", err.Error())
	}

	slog.InfoContext(ctx, "Service: Login successful", "userID", userInfo.UserId, "email", userInfo.Email)
	return &pb.LoginResponse{
		User: userInfo, AccessToken: signedAccessToken, RefreshToken: rawRefreshToken, // Client'a ham token'ı gönder
		ExpiresIn: int32(time.Until(accessTokenExp).Seconds()),
	}, nil
}

func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	slog.InfoContext(ctx, "Service: ValidateToken request initiated")
	if req.Token == "" {
		slog.WarnContext(ctx, "Service: ValidateToken failed - token is empty")
		return nil, status.Errorf(codes.InvalidArgument, "Token is required")
	}

	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		slog.WarnContext(ctx, "Service: Access token parsing or validation failed", "error", err.Error())
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, status.Errorf(codes.Unauthenticated, "token is expired")
		}
		return nil, status.Errorf(codes.Unauthenticated, "Invalid access token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userIDStr, okUserID := claims["sub"].(string)
		if !okUserID {
			slog.WarnContext(ctx, "Service: Invalid token claims - missing user_id (sub)")
			return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims (sub)")
		}
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			slog.WarnContext(ctx, "Service: Invalid user_id format in token", "userID_str", userIDStr, "error", err.Error())
			return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims (user_id format)")
		}

		userInfo, err := s.userRepo.GetUserByID(ctx, userID)
		if err != nil {
			slog.WarnContext(ctx, "Service: User not found for token validation", "userID", userIDStr, "error", err.Error())
			return nil, status.Errorf(codes.Unauthenticated, "User associated with token not found")
		}
		if !userInfo.IsActive {
			slog.WarnContext(ctx, "Service: Inactive user account during token validation", "userID", userInfo.UserId)
			return nil, status.Errorf(codes.PermissionDenied, "User account is disabled")
		}

		slog.InfoContext(ctx, "Service: Access token validated successfully", "userID", userInfo.UserId, "email", userInfo.Email)
		return &pb.ValidateTokenResponse{User: userInfo}, nil
	}

	slog.WarnContext(ctx, "Service: Invalid access token (claims not valid or token invalid structure)")
	return nil, status.Errorf(codes.Unauthenticated, "Invalid access token")
}

func (s *AuthServiceServer) RefreshAccessToken(ctx context.Context, req *pb.RefreshAccessTokenRequest) (*pb.LoginResponse, error) {
	slog.InfoContext(ctx, "Service: RefreshAccessToken request received")
	if req.RefreshToken == "" {
		slog.WarnContext(ctx, "Service: RefreshAccessToken failed - refresh token is empty")
		return nil, status.Errorf(codes.InvalidArgument, "Refresh token is required")
	}

	hashedRefreshToken := hashToken(req.RefreshToken) // Gelen ham token'ı hash'le
	dbToken, err := s.userRepo.GetRefreshTokenByHash(ctx, hashedRefreshToken)
	if err != nil {
		slog.WarnContext(ctx, "Service: Invalid or expired refresh token on GetByHash", "error", err.Error(), "provided_token_hash_prefix", hashedRefreshToken[:min(8, len(hashedRefreshToken))])
		return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired refresh token")
	}

	// Eski refresh token'ı hemen revoke et (Token Rotasyonu)
	if err := s.userRepo.RevokeRefreshTokenByHash(ctx, dbToken.TokenHash); err != nil {
		slog.ErrorContext(ctx, "Service: Failed to revoke old refresh token during rotation", "userID", dbToken.UserID.String(), "tokenHash", dbToken.TokenHash, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to process refresh token rotation")
	}

	userInfo, err := s.userRepo.GetUserByID(ctx, dbToken.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "Service: User for refresh token not found", "userID", dbToken.UserID.String(), "error", err)
		return nil, status.Errorf(codes.Unauthenticated, "User for refresh token is invalid")
	}
	if !userInfo.IsActive {
		slog.WarnContext(ctx, "Service: User for refresh token is not active", "userID", dbToken.UserID.String())
		return nil, status.Errorf(codes.PermissionDenied, "User account (for refresh token) is disabled")
	}

	// Yeni Access Token
	accessTokenExp := time.Now().Add(time.Hour * 1)
	accessClaims := jwt.MapClaims{
		"sub": userInfo.UserId, "email": userInfo.Email, "roles": userInfo.Roles,
		"exp": accessTokenExp.Unix(), "iat": time.Now().Unix(), "jti": uuid.NewString(),
	}
	newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedNewAccessToken, errToken := newAccessToken.SignedString(s.jwtSecret)
	if errToken != nil {
		slog.ErrorContext(ctx, "Service: Error signing new access token during refresh", "userID", userInfo.UserId, "error", errToken.Error())
		return nil, status.Errorf(codes.Internal, "Could not generate new access token")
	}

	// Yeni Refresh Token
	newRawRefreshToken := uuid.NewString()
	newHashedRefreshToken := hashToken(newRawRefreshToken)
	newRefreshTokenExp := time.Now().Add(time.Hour * 24 * 30)
	if errStore := s.userRepo.StoreRefreshToken(ctx, dbToken.UserID, newHashedRefreshToken, newRefreshTokenExp); errStore != nil {
		slog.ErrorContext(ctx, "Service: Failed to store new refresh token during rotation", "userID", dbToken.UserID.String(), "error", errStore.Error())
		// Bu durumda eski token revoke edildi ama yenisi kaydedilemedi. Bu kritik bir durum.
		// Kullanıcıya login olmasını söylemek en güvenlisi.
		return nil, status.Errorf(codes.Internal, "Failed to complete token refresh, please log in again")
	}

	slog.InfoContext(ctx, "Service: Access token refreshed successfully", "userID", userInfo.UserId)
	return &pb.LoginResponse{
		User: userInfo, AccessToken: signedNewAccessToken, RefreshToken: newRawRefreshToken,
		ExpiresIn: int32(time.Until(accessTokenExp).Seconds()),
	}, nil
}

func (s *AuthServiceServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	slog.InfoContext(ctx, "Service: Logout request received")
	if req.RefreshToken == "" {
		slog.InfoContext(ctx, "Service: Logout (no server-side refresh token provided to revoke)")
		return &pb.LogoutResponse{Message: "Logged out (client should clear tokens). No server-side refresh token provided to revoke."}, nil
	}

	hashedRefreshToken := hashToken(req.RefreshToken)
	err := s.userRepo.RevokeRefreshTokenByHash(ctx, hashedRefreshToken)
	if err != nil {
		// Hata olsa bile client'a başarılı dönülebilir, ama logla
		slog.ErrorContext(ctx, "Service: Error revoking refresh token during logout", "error", err.Error(), "provided_token_hash_prefix", hashedRefreshToken[:min(8, len(hashedRefreshToken))])
		// Belki de burada bir hata dönmek daha doğru olur, client'ın token'ı silemediğini bilmesi için.
		// return nil, status.Errorf(codes.Internal, "Failed to revoke refresh token on server")
		return &pb.LogoutResponse{Message: "Logout processed, but server-side token revocation encountered an issue."}, nil
	}

	slog.InfoContext(ctx, "Service: Refresh token revoked successfully during logout")
	return &pb.LogoutResponse{Message: "Successfully logged out and refresh token revoked."}, nil
}

// --- Şifre Sıfırlama RPC Implementasyonları ---

func (s *AuthServiceServer) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
	slog.InfoContext(ctx, "Service: RequestPasswordReset request received", "email", req.Email)

	if req.Email == "" {
		slog.WarnContext(ctx, "Service: RequestPasswordReset failed - email is required")
		return nil, status.Errorf(codes.InvalidArgument, "Email is required")
	}

	userInfo, _, isActive, err := s.userRepo.GetUserByEmail(ctx, req.Email)

	if err != nil || (userInfo != nil && !isActive) {
		if err != nil && err.Error() != fmt.Sprintf("user with email '%s' not found", req.Email) { // Sadece "not found" dışındaki DB hatalarını logla
			slog.ErrorContext(ctx, "Service: DB error during password reset request, but returning generic success", "email", req.Email, "error", err.Error())
		} else if userInfo != nil && !isActive {
			slog.WarnContext(ctx, "Service: Password reset requested for inactive user, returning generic success", "email", req.Email, "userID", userInfo.UserId)
		} else {
			slog.InfoContext(ctx, "Service: Password reset requested for non-existent email, returning generic success", "email", req.Email)
		}
		// Güvenlik: Kullanıcıya e-postanın varlığı hakkında bilgi sızdırma.
		return &pb.RequestPasswordResetResponse{
			Message:         "If an account with that email exists, a password reset link has been sent.",
			ExpiresInSeconds: int32(passwordResetTokenExpiry.Seconds()),
		}, nil
	}
	// Buraya geldiyse, kullanıcı bulundu ve aktif.
	parsedUserID, _ := uuid.Parse(userInfo.UserId) // GetUserByEmail UserInfo döndüğü için ID'yi parse etmeliyiz.

	rawResetToken, err := generateSecureRandomToken(passwordResetTokenBytesLength)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Failed to generate password reset token", "userID", parsedUserID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to initiate password reset")
	}
	hashedResetToken := hashToken(rawResetToken) // Ham token'ı hash'le
	expiresAt := time.Now().Add(passwordResetTokenExpiry)

	if err := s.userRepo.StorePasswordResetToken(ctx, parsedUserID, hashedResetToken, expiresAt); err != nil {
		slog.ErrorContext(ctx, "Service: Failed to store password reset token", "userID", parsedUserID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to initiate password reset process")
	}

	// TODO: E-posta gönderme mekanizmasını implemente et.
	// Şimdilik log'a yazdırıyoruz ve token'ı da logluyoruz (SADECE DEBUG İÇİN).
	resetLink := fmt.Sprintf("https://voya.go/reset-password?token=%s", rawResetToken) // raw token'ı linke ekle
	slog.InfoContext(ctx, "MOCK_EMAIL: Password reset email (would be sent)",
		"to", userInfo.Email,
		"subject", "VoyaGo Password Reset",
		"reset_link_for_testing_only", resetLink,     // Üretimde bu log kaldırılmalı
		"raw_token_for_testing_only", rawResetToken, // Üretimde bu log kaldırılmalı
	)

	return &pb.RequestPasswordResetResponse{
		Message:         "If an account with that email exists, a password reset link has been sent.",
		ExpiresInSeconds: int32(passwordResetTokenExpiry.Seconds()),
	}, nil
}

func (s *AuthServiceServer) ConfirmPasswordReset(ctx context.Context, req *pb.ConfirmPasswordResetRequest) (*pb.ConfirmPasswordResetResponse, error) {
	slog.InfoContext(ctx, "Service: ConfirmPasswordReset request received")

	if req.ResetToken == "" || len(req.NewPassword) < 8 {
		slog.WarnContext(ctx, "Service: ConfirmPasswordReset failed - invalid token or new password too short")
		return nil, status.Errorf(codes.InvalidArgument, "Valid reset token and new password (min 8 chars) are required")
	}

	hashedResetToken := hashToken(req.ResetToken)
	dbResetToken, err := s.userRepo.GetValidPasswordResetTokenByHash(ctx, hashedResetToken)
	if err != nil {
		slog.WarnContext(ctx, "Service: ConfirmPasswordReset - GetValidPasswordResetTokenByHash failed", "error", err.Error())
		return nil, status.Errorf(codes.InvalidArgument, "Invalid or expired reset token") // "already used" kısmı kaldırıldı
	}

	newPasswordHash, err := hashPassword(req.NewPassword)
	if err != nil {
		slog.ErrorContext(ctx, "Service: ConfirmPasswordReset - error hashing new password", "userID", dbResetToken.UserID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to process new password")
	}

	if err := s.userRepo.UpdateUserPassword(ctx, dbResetToken.UserID, newPasswordHash); err != nil {
		slog.ErrorContext(ctx, "Service: ConfirmPasswordReset - error updating user password", "userID", dbResetToken.UserID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to update password")
	}

	if err := s.userRepo.MarkPasswordResetTokenAsUsed(ctx, dbResetToken.TokenHash); err != nil {
		slog.ErrorContext(ctx, "Service: ConfirmPasswordReset - failed to mark reset token as used", "userID", dbResetToken.UserID.String(), "tokenHash", dbResetToken.TokenHash, "error", err.Error())
		// Şifre güncellendi, bu hata kritik değil ama loglanmalı.
	}

	// Güvenlik amacıyla, şifre sıfırlandıktan sonra tüm aktif refresh token'ları iptal et
	if err := s.userRepo.RevokeAllRefreshTokensForUser(ctx, dbResetToken.UserID); err != nil {
		slog.WarnContext(ctx, "Service: ConfirmPasswordReset - failed to revoke refresh tokens", "userID", dbResetToken.UserID.String(), "error", err.Error())
	}

	slog.InfoContext(ctx, "Service: Password successfully updated via reset token", "userID", dbResetToken.UserID.String())
	return &pb.ConfirmPasswordResetResponse{
		Message: "Password successfully updated. You can now log in with your new password.",
	}, nil
}


// Diğer RPC'ler için Unimplemented stub'ları (slog eklendi)
func (s *AuthServiceServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	slog.InfoContext(ctx, "Service: ChangePassword request received")
	if req.AccessToken == "" || req.OldPassword == "" || len(req.NewPassword) < 8 {
		slog.WarnContext(ctx, "Service: ChangePassword failed - missing required fields or new password too short")
		return nil, status.Errorf(codes.InvalidArgument, "Access token, old password, and new password (min 8 chars) are required")
	}

	// 1. Access Token'ı doğrula
	validateRes, err := s.ValidateToken(ctx, &pb.ValidateTokenRequest{Token: req.AccessToken})
	if err != nil {
		slog.WarnContext(ctx, "Service: ChangePassword failed - invalid access token", "error", err)
		return nil, err // ValidateToken zaten uygun gRPC hatasını döner
	}
	userInfo := validateRes.User
	userID, _ := uuid.Parse(userInfo.UserId)

	// 2. Veritabanından kullanıcının mevcut şifre hash'ini al (GetUserByEmail üzerinden)
	// Bu RPC, passwordHash'i de dönüyor.
	_, storedPasswordHash, isActive, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		slog.ErrorContext(ctx, "Service: ChangePassword failed - could not fetch user for old password check", "userID", userID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to process your request")
	}
	if !isActive { // Bu kontrol ValidateToken içinde de var ama yine de yapalım
		slog.WarnContext(ctx, "Service: ChangePassword failed - user account disabled", "userID", userID.String())
		return nil, status.Errorf(codes.PermissionDenied, "User account is disabled")
	}

	// 3. Eski şifreyi doğrula
	if !checkPasswordHash(req.OldPassword, storedPasswordHash) {
		slog.WarnContext(ctx, "Service: ChangePassword failed - incorrect old password", "userID", userID.String())
		return nil, status.Errorf(codes.Unauthenticated, "Incorrect old password")
	}

	// 4. Yeni şifreyi hash'le
	newPasswordHash, err := hashPassword(req.NewPassword)
	if err != nil {
		slog.ErrorContext(ctx, "Service: ChangePassword failed - error hashing new password", "userID", userID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to process new password")
	}

	// 5. Yeni şifreyi veritabanında güncelle
	if err := s.userRepo.UpdateUserPassword(ctx, userID, newPasswordHash); err != nil {
		slog.ErrorContext(ctx, "Service: ChangePassword failed - error updating password in repository", "userID", userID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to update password")
	}

	// 6. Şifre değiştiği için kullanıcının diğer tüm aktif oturumlarını (refresh token'larını) sonlandır
	if err := s.userRepo.RevokeAllRefreshTokensForUser(ctx, userID); err != nil {
		slog.WarnContext(ctx, "Service: ChangePassword - failed to revoke all refresh tokens", "userID", userID.String(), "error", err.Error())
	}

	slog.InfoContext(ctx, "Service: Password changed successfully by user", "userID", userID.String())
	return &pb.ChangePasswordResponse{Message: "Password changed successfully."}, nil
}

// src/authservice/service/auth_service.go

func (s *AuthServiceServer) RequestEmailVerification(ctx context.Context, req *pb.RequestEmailVerificationRequest) (*pb.RequestEmailVerificationResponse, error) {
	slog.InfoContext(ctx, "Service: RequestEmailVerification request received")

	if req.AccessToken == "" {
		slog.WarnContext(ctx, "Service: RequestEmailVerification failed - access token is required")
		return nil, status.Errorf(codes.InvalidArgument, "Access token is required")
	}

	// 1. Access Token'ı doğrula ve kullanıcı bilgilerini al
	validateRes, err := s.ValidateToken(ctx, &pb.ValidateTokenRequest{Token: req.AccessToken})
	if err != nil {
		slog.WarnContext(ctx, "Service: RequestEmailVerification failed - invalid access token", "error", err)
		return nil, err // ValidateToken zaten uygun gRPC hatasını döner (örn: Unauthenticated)
	}
	userInfo := validateRes.User // Bu UserInfo *pb.UserInfo tipinde olmalı
	if userInfo.EmailVerified {
		slog.InfoContext(ctx, "Service: Email already verified for user", "userID", userInfo.UserId, "email", userInfo.Email)
		return &pb.RequestEmailVerificationResponse{
			Message: "Your email address is already verified.",
		}, nil
	}

	parsedUserID, errParse := uuid.Parse(userInfo.UserId)
	if errParse != nil {
		slog.ErrorContext(ctx, "Service: Failed to parse UserID from validated token", "userID_str", userInfo.UserId, "error", errParse.Error())
		return nil, status.Errorf(codes.Internal, "Internal server error processing user ID")
	}

	// 2. Güvenli bir doğrulama token'ı üret
	rawVerificationToken, err := generateSecureRandomToken(emailVerificationTokenBytesLength)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Failed to generate email verification token", "userID", parsedUserID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to initiate email verification")
	}
	hashedVerificationToken := hashToken(rawVerificationToken) // Ham token'ı hash'le
	expiresAt := time.Now().Add(emailVerificationTokenExpiry)

	// 3. Token'ı veritabanında sakla
	// StoreEmailVerificationToken, userID, email, tokenHash, expiresAt alır.
	// userInfo.Email'i kullanıyoruz.
	if err := s.userRepo.StoreEmailVerificationToken(ctx, parsedUserID, userInfo.Email, hashedVerificationToken, expiresAt); err != nil {
		slog.ErrorContext(ctx, "Service: Failed to store email verification token in repository", "userID", parsedUserID.String(), "email", userInfo.Email, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to initiate email verification process")
	}

	// 4. Kullanıcıya doğrulama linkini içeren bir e-posta gönder (ŞİMDİLİK MOCK/LOG)
	// TODO: Gerçek bir e-posta gönderme servisi entegre et.
	verificationLink := fmt.Sprintf("https://voya.go/verify-email?token=%s", rawVerificationToken) // raw token'ı linke ekle
	slog.InfoContext(ctx, "MOCK_EMAIL_SERVICE: Sending email verification email",
		"to", userInfo.Email,
		"subject", "VoyaGo Email Verification",
		"verification_link_for_debug", verificationLink,     // DEBUG İÇİN LOGLA, ÜRETİMDE KALDIR
		"raw_token_for_debug", rawVerificationToken,         // DEBUG İÇİN LOGLA, ÜRETİMDE KALDIR
	)

	slog.InfoContext(ctx, "Service: Email verification token generated and (mock) email sent", "userID", userInfo.UserId, "email", userInfo.Email)
	return &pb.RequestEmailVerificationResponse{
		Message:         "A verification link has been sent to your email address.",
		ExpiresInSeconds: int32(emailVerificationTokenExpiry.Seconds()),
	}, nil
}
// src/authservice/service/auth_service.go

func (s *AuthServiceServer) ConfirmEmailVerification(ctx context.Context, req *pb.ConfirmEmailVerificationRequest) (*pb.ConfirmEmailVerificationResponse, error) {
	slog.InfoContext(ctx, "Service: ConfirmEmailVerification request received")

	if req.VerificationToken == "" {
		slog.WarnContext(ctx, "Service: ConfirmEmailVerification failed - verification token is required")
		return nil, status.Errorf(codes.InvalidArgument, "Verification token is required")
	}

	hashedVerificationToken := hashToken(req.VerificationToken) // Gelen ham token'ı hash'le

	// 1. Veritabanından geçerli (süresi dolmamış, kullanılmamış) token'ı al
	// GetValidEmailVerificationTokenByHash *repository.EmailVerificationToken döner
	dbVerificationToken, err := s.userRepo.GetValidEmailVerificationTokenByHash(ctx, hashedVerificationToken)
	if err != nil {
		slog.WarnContext(ctx, "Service: ConfirmEmailVerification - GetValidEmailVerificationTokenByHash failed", "error", err.Error(), "provided_token_hash_prefix", hashedVerificationToken[:min(8, len(hashedVerificationToken))])
		return nil, status.Errorf(codes.InvalidArgument, "Invalid, expired, or already used verification token")
	}

	// 2. Kullanıcının e-postasını doğrulanmış olarak işaretle
	if err := s.userRepo.MarkUserEmailAsVerified(ctx, dbVerificationToken.UserID); err != nil {
		slog.ErrorContext(ctx, "Service: ConfirmEmailVerification - error marking user email as verified", "userID", dbVerificationToken.UserID.String(), "email", dbVerificationToken.Email, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Failed to verify email address")
	}

	// 3. Kullanılan doğrulama token'ını geçersiz kıl (consumed=true)
	if err := s.userRepo.MarkEmailVerificationTokenAsUsed(ctx, dbVerificationToken.TokenHash); err != nil {
		// E-posta doğrulandı, bu hata kritik değil ama loglanmalı.
		slog.ErrorContext(ctx, "Service: ConfirmEmailVerification - failed to mark verification token as used", "userID", dbVerificationToken.UserID.String(), "tokenHash", dbVerificationToken.TokenHash, "error", err.Error())
	}

	// Güncellenmiş kullanıcı bilgilerini alıp dön
	updatedUserInfo, err := s.userRepo.GetUserByID(ctx, dbVerificationToken.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "Service: ConfirmEmailVerification - failed to fetch updated user info", "userID", dbVerificationToken.UserID.String(), "error", err.Error())
		// E-posta doğrulandı, ama güncel bilgiyi dönemiyoruz. Mesajla idare edelim.
		return &pb.ConfirmEmailVerificationResponse{
			Message: "Email successfully verified. User details could not be retrieved.",
		}, nil
	}

	slog.InfoContext(ctx, "Service: Email successfully verified for user", "userID", dbVerificationToken.UserID.String(), "email", dbVerificationToken.Email)
	return &pb.ConfirmEmailVerificationResponse{
		Message: "Email successfully verified.",
		User:    updatedUserInfo, // E-postası doğrulanmış kullanıcı bilgisi
	}, nil
}
func (s *AuthServiceServer) UpdateUserMetadata(ctx context.Context, req *pb.UpdateUserMetadataRequest) (*pb.UpdateUserMetadataResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "UpdateUserMetadata")
	// TODO: Access token'ı doğrulama, full_name'i güncelleme, (ileride) user_metadata JSONB alanını güncelleme
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserMetadata not implemented")
}