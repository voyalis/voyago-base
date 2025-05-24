package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/voyalis/voyago-base/src/authservice/repository" // Repository paketini import ediyoruz
)

// UserRepository interface'i, AuthService'in repository'ye olan bağımlılığını tanımlar.
// Bu, repository paketindeki UserRepoInterface ile aynı olmalı.
// Dependency Inversion için bu pakette tanımlamak daha doğru olabilir.
type UserRepository interface {
	CreateUser(ctx context.Context, email, passwordHash, fullName string) (*repository.User, error)
	GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string /*passwordHash*/, bool /*isActive*/, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error)
	StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error)
	RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error
	UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error
}

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	userRepo  UserRepository // Artık bu paketteki interface'i kullanıyoruz
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

// ... (hashPassword, checkPasswordHash, hashRefreshToken, min fonksiyonları aynı kalır) ...
func hashPassword(password string) (string, error) { bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12); return string(bytes), err }
func checkPasswordHash(password, hash string) bool { return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil }
func hashRefreshToken(token string) string { hasher := sha256.New(); hasher.Write([]byte(token)); return hex.EncodeToString(hasher.Sum(nil)) }
func min(a, b int) int { if a < b { return a }; return b }


// Register RPC metodu
func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	slog.InfoContext(ctx, "Service: Register request received", "email", req.Email, "fullName", req.FullName)
	if req.Email == "" || req.Password == "" { slog.WarnContext(ctx, "Service: Register failed - missing email or password", "email", req.Email); return nil, status.Errorf(codes.InvalidArgument, "Email and password are required") }
	if len(req.Password) < 8 { slog.WarnContext(ctx, "Service: Register failed - password too short", "email", req.Email); return nil, status.Errorf(codes.InvalidArgument, "Password must be at least 8 characters long") }
	hashedPassword, err := hashPassword(req.Password)
	if err != nil { slog.ErrorContext(ctx, "Service: Error hashing password", "email", req.Email, "error", err.Error()); return nil, status.Errorf(codes.Internal, "Failed to process password") }
	
	// CreateUser *repository.User dönecek şekilde ayarlanmıştı.
	createdRepoUser, err := s.userRepo.CreateUser(ctx, req.Email, hashedPassword, req.FullName)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") { slog.WarnContext(ctx, "Service: User registration conflict", "email", req.Email, "error", err.Error()); return nil, status.Errorf(codes.AlreadyExists, err.Error()) }
		slog.ErrorContext(ctx, "Service: User creation failed in repository", "email", req.Email, "error", err.Error()); return nil, status.Errorf(codes.Internal, "Failed to register user")
	}

	// CreateUser sonrası güncel bilgiyi GetUserByID ile çekiyoruz.
	userInfo, err := s.userRepo.GetUserByID(ctx, createdRepoUser.ID)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Registered user but failed to fetch details for response", "userID", createdRepoUser.ID.String(), "error", err.Error())
		return nil, status.Errorf(codes.Internal, "User registered but failed to retrieve details")
	}
	
	slog.InfoContext(ctx, "Service: User registered successfully", "userID", userInfo.UserId, "email", userInfo.Email)
	return &pb.RegisterResponse{User: userInfo, Message: "User registered successfully"}, nil
}

// Login RPC metodu
func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	slog.InfoContext(ctx, "Service: Login attempt started", "email", req.Email)
	// ... (kullanıcı doğrulama ve hata kontrolleri aynı) ...
	if req.Email == "" || req.Password == "" { slog.WarnContext(ctx, "Service: Login failed - missing email or password", "email", req.Email); return nil, status.Errorf(codes.InvalidArgument, "Email and password are required") }
	userInfo, storedPasswordHash, isActive, err := s.userRepo.GetUserByEmail(ctx, req.Email)
	if err != nil { slog.WarnContext(ctx, "Service: Login failed - GetUserByEmail", "email", req.Email, "error", err.Error()); return nil, status.Errorf(codes.Unauthenticated, "Invalid email or password") }
	if !isActive { slog.WarnContext(ctx, "Service: Login blocked - inactive account", "userID", userInfo.UserId, "email", req.Email); return nil, status.Errorf(codes.PermissionDenied, "User account is disabled") }
	if !checkPasswordHash(req.Password, storedPasswordHash) { slog.WarnContext(ctx, "Service: Login failed - incorrect password", "userID", userInfo.UserId, "email", req.Email); return nil, status.Errorf(codes.Unauthenticated, "Invalid email or password") }


	// Access Token
	accessTokenExp := time.Now().Add(time.Hour * 1)
	accessClaims := jwt.MapClaims{
		"sub":   userInfo.UserId,
		"email": userInfo.Email,
		"roles": userInfo.Roles,
		"exp":   accessTokenExp.Unix(),
		"iat":   time.Now().Unix(),
		"jti":   uuid.NewString(), // YENİ: Benzersiz JWT ID eklendi
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, err := accessToken.SignedString(s.jwtSecret)
	if err != nil {
		slog.ErrorContext(ctx, "Service: Error signing access token", "userID", userInfo.UserId, "error", err.Error())
		return nil, status.Errorf(codes.Internal, "Could not generate access token")
	}

	// Refresh Token
	rawRefreshToken := uuid.NewString()
	hashedRefreshToken := hashRefreshToken(rawRefreshToken)
	refreshTokenExp := time.Now().Add(time.Hour * 24 * 30)
	parsedUserID, _ := uuid.Parse(userInfo.UserId)
	if err := s.userRepo.StoreRefreshToken(ctx, parsedUserID, hashedRefreshToken, refreshTokenExp); err != nil {
		slog.ErrorContext(ctx, "Service: Failed to store refresh token, but proceeding with login", "userID", userInfo.UserId, "error", err.Error())
	}
	if err := s.userRepo.UpdateUserLastSignInAt(ctx, parsedUserID); err != nil {
		slog.WarnContext(ctx, "Service: Failed to update last_sign_in_at", "userID", userInfo.UserId, "error", err.Error())
	}

	slog.InfoContext(ctx, "Service: Login successful", "userID", userInfo.UserId, "email", userInfo.Email)
	return &pb.LoginResponse{
		User:         userInfo,
		AccessToken:  signedAccessToken,
		RefreshToken: rawRefreshToken,
		ExpiresIn:    int32(time.Until(accessTokenExp).Seconds()),
	}, nil
}

// ValidateToken RPC metodu
func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	slog.InfoContext(ctx, "Service: ValidateToken request initiated")
	if req.Token == "" { slog.WarnContext(ctx, "Service: ValidateToken failed - token is empty"); return nil, status.Errorf(codes.InvalidArgument, "Token is required") }
	
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"]) }
		return s.jwtSecret, nil
	})
	if err != nil { slog.WarnContext(ctx, "Service: Access token parsing or validation failed", "error", err.Error()); return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired access token") }

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userIDStr, okUserID := claims["sub"].(string)
		if !okUserID { slog.WarnContext(ctx, "Service: Invalid token claims - missing user_id (sub)"); return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims (sub)") }
		userID, err := uuid.Parse(userIDStr)
		if err != nil { slog.WarnContext(ctx, "Service: Invalid user_id format in token", "userID_str", userIDStr, "error", err.Error()); return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims (user_id format)") }
		userInfo, err := s.userRepo.GetUserByID(ctx, userID)
		if err != nil { slog.WarnContext(ctx, "Service: User not found for token validation", "userID", userIDStr, "error", err.Error()); return nil, status.Errorf(codes.Unauthenticated, "User associated with token not found") }
		if !userInfo.IsActive { slog.WarnContext(ctx, "Service: Inactive user account during token validation", "userID", userInfo.UserId); return nil, status.Errorf(codes.PermissionDenied, "User account is disabled") }
		slog.InfoContext(ctx, "Service: Access token validated successfully", "userID", userInfo.UserId, "email", userInfo.Email)
		return &pb.ValidateTokenResponse{User: userInfo}, nil
	}
	slog.WarnContext(ctx, "Service: Invalid access token"); return nil, status.Errorf(codes.Unauthenticated, "Invalid access token")
}

// RefreshAccessToken RPC metodu
func (s *AuthServiceServer) RefreshAccessToken(ctx context.Context, req *pb.RefreshAccessTokenRequest) (*pb.LoginResponse, error) {
	slog.InfoContext(ctx, "Service: RefreshAccessToken request received")
	// ... (refresh token doğrulama, eskiyi revoke etme, kullanıcıyı çekme kısımları aynı) ...
	if req.RefreshToken == "" { slog.WarnContext(ctx, "Service: RefreshAccessToken failed - refresh token is empty"); return nil, status.Errorf(codes.InvalidArgument, "Refresh token is required") }
	hashedRefreshToken := hashRefreshToken(req.RefreshToken)
	dbToken, err := s.userRepo.GetRefreshTokenByHash(ctx, hashedRefreshToken)
	if err != nil { slog.WarnContext(ctx, "Service: Invalid or expired refresh token", "error", err.Error(), "provided_token_hash_prefix", hashedRefreshToken[:min(8,len(hashedRefreshToken))]); return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired refresh token") }
	if err := s.userRepo.RevokeRefreshTokenByHash(ctx, dbToken.TokenHash); err != nil { slog.ErrorContext(ctx, "Service: Failed to revoke old refresh token", "userID", dbToken.UserID.String(), "error", err.Error()); return nil, status.Errorf(codes.Internal, "Failed to process refresh token rotation") }
	userInfo, err := s.userRepo.GetUserByID(ctx, dbToken.UserID)
	if err != nil || (userInfo != nil && !userInfo.IsActive) { slog.ErrorContext(ctx, "Service: User for refresh token not found or not active", "userID", dbToken.UserID.String(), "error", err); return nil, status.Errorf(codes.Unauthenticated, "User for refresh token is invalid") }
	if userInfo == nil && err == nil { slog.ErrorContext(ctx, "Service: GetUserByID inconsistency for refresh token", "userID", dbToken.UserID.String()); return nil, status.Errorf(codes.Internal, "Internal error during refresh") }


	// Yeni Access Token
	accessTokenExp := time.Now().Add(time.Hour * 1)
	accessClaims := jwt.MapClaims{
		"sub":   userInfo.UserId,
		"email": userInfo.Email,
		"roles": userInfo.Roles,
		"exp":   accessTokenExp.Unix(),
		"iat":   time.Now().Unix(),
		"jti":   uuid.NewString(), // YENİ: Benzersiz JWT ID eklendi
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccessToken, errToken := accessToken.SignedString(s.jwtSecret)
	if errToken != nil {
		slog.ErrorContext(ctx, "Service: Error signing new access token during refresh", "userID", userInfo.UserId, "error", errToken.Error())
		return nil, status.Errorf(codes.Internal, "Could not generate new access token")
	}

	// Yeni Refresh Token
	newRawRefreshToken := uuid.NewString()
	newHashedRefreshToken := hashRefreshToken(newRawRefreshToken)
	newRefreshTokenExp := time.Now().Add(time.Hour * 24 * 30)
	if errStore := s.userRepo.StoreRefreshToken(ctx, dbToken.UserID, newHashedRefreshToken, newRefreshTokenExp); errStore != nil {
		slog.ErrorContext(ctx, "Service: Failed to store new refresh token during rotation", "userID", dbToken.UserID.String(), "error", errStore.Error())
		return nil, status.Errorf(codes.Internal, "Could not store new refresh token")
	}

	slog.InfoContext(ctx, "Service: Access token refreshed successfully", "userID", userInfo.UserId)
	return &pb.LoginResponse{
		User:         userInfo,
		AccessToken:  signedAccessToken,
		RefreshToken: newRawRefreshToken,
		ExpiresIn:    int32(time.Until(accessTokenExp).Seconds()),
	}, nil
}

// Logout RPC metodu
func (s *AuthServiceServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	slog.InfoContext(ctx, "Service: Logout request received")
	if req.RefreshToken == "" { slog.InfoContext(ctx, "Service: Logout (no server-side refresh token provided)"); return &pb.LogoutResponse{Message: "Logged out. No server-side refresh token to revoke."}, nil }
	
	hashedRefreshToken := hashRefreshToken(req.RefreshToken)
	err := s.userRepo.RevokeRefreshTokenByHash(ctx, hashedRefreshToken)
	if err != nil { slog.ErrorContext(ctx, "Service: Error revoking refresh token during logout", "error", err.Error()); return &pb.LogoutResponse{Message: "Logout processed, server-side token revocation failed."}, nil }
	
	slog.InfoContext(ctx, "Service: Refresh token revoked successfully during logout")
	return &pb.LogoutResponse{Message: "Successfully logged out and refresh token revoked."}, nil
}

// Diğer RPC'ler için Unimplemented stub'ları (slog eklendi)
func (s *AuthServiceServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "ChangePassword")
	return nil, status.Errorf(codes.Unimplemented, "method ChangePassword not implemented")
}
func (s *AuthServiceServer) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "RequestPasswordReset")
	return nil, status.Errorf(codes.Unimplemented, "method RequestPasswordReset not implemented")
}
func (s *AuthServiceServer) ConfirmPasswordReset(ctx context.Context, req *pb.ConfirmPasswordResetRequest) (*pb.ConfirmPasswordResetResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "ConfirmPasswordReset")
	return nil, status.Errorf(codes.Unimplemented, "method ConfirmPasswordReset not implemented")
}
func (s *AuthServiceServer) RequestEmailVerification(ctx context.Context, req *pb.RequestEmailVerificationRequest) (*pb.RequestEmailVerificationResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "RequestEmailVerification")
	return nil, status.Errorf(codes.Unimplemented, "method RequestEmailVerification not implemented")
}
func (s *AuthServiceServer) ConfirmEmailVerification(ctx context.Context, req *pb.ConfirmEmailVerificationRequest) (*pb.ConfirmEmailVerificationResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "ConfirmEmailVerification")
	return nil, status.Errorf(codes.Unimplemented, "method ConfirmEmailVerification not implemented")
}
func (s *AuthServiceServer) UpdateUserMetadata(ctx context.Context, req *pb.UpdateUserMetadataRequest) (*pb.UpdateUserMetadataResponse, error) {
	slog.WarnContext(ctx, "RPC method not implemented", "method", "UpdateUserMetadata")
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserMetadata not implemented")
}