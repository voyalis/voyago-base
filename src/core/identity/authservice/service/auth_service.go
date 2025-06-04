package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/interceptor"
	"github.com/voyalis/voyago-base/src/core/identity/authservice/repository"
)

const (
    passwordResetTokenBytesLength     = 32
    passwordResetTokenExpiry          = 15 * time.Minute
    emailVerificationTokenBytesLength = 32
    emailVerificationTokenExpiry      = 24 * time.Hour
    accessTokenExpiryDuration         = time.Hour * 1
    refreshTokenExpiryDuration        = time.Hour * 24 * 30
)

type UserRepository interface {
    CreateUser(ctx context.Context, email, passwordHash, fullName string) (*repository.User, error)
    GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error)
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
    GetValidEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*repository.EmailVerificationToken, error)
    MarkEmailVerificationTokenAsUsed(ctx context.Context, tokenHash string) error
    MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error
    UpdateUserFullName(ctx context.Context, userID uuid.UUID, newFullName string) error
}

type AuthServiceServer struct {
    pb.UnimplementedAuthServiceServer
    userRepo    UserRepository
    jwtSecret   []byte
    rateLimiter *interceptor.IPRateLimiter
}

func NewAuthServiceServer(repo UserRepository, secretKeyVal string, rlConfig interceptor.RateLimiterConfig) *AuthServiceServer {
    if secretKeyVal == "" {
        slog.Error("JWT_SECRET_KEY must be set. Exiting.")
        panic("JWT_SECRET_KEY is empty in NewAuthServiceServer")
    }
    return &AuthServiceServer{
        userRepo:    repo,
        jwtSecret:   []byte(secretKeyVal),
        rateLimiter: interceptor.NewIPRateLimiter(rlConfig),
    }
}

func (s *AuthServiceServer) RateLimitInterceptor() grpc.UnaryServerInterceptor {
    if s.rateLimiter == nil {
        slog.Warn("AuthServiceServer: RateLimiter is nil, using passthrough interceptor.")
        return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
            return handler(ctx, req)
        }
    }
    return s.rateLimiter.UnaryServerInterceptor()
}

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
    return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func hashToken(token string) string {
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

// Register
func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
    slog.InfoContext(ctx, "Service: Register request", "email", req.Email, "fullName", req.FullName)
    if req.Email == "" || req.Password == "" {
        slog.WarnContext(ctx, "Service: Register failed - missing email or password", "email", req.Email)
        return nil, status.Errorf(codes.InvalidArgument, "Email and password are required")
    }
    if len(req.Password) < 8 {
        slog.WarnContext(ctx, "Service: Register failed - password too short", "email", req.Email)
        return nil, status.Errorf(codes.InvalidArgument, "Password must be at least 8 characters long")
    }

    hashedPassword, err := hashPassword(req.Password)
    if err != nil {
        slog.ErrorContext(ctx, "Service: Error hashing password", "email", req.Email, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to process password")
    }

    createdUser, err := s.userRepo.CreateUser(ctx, req.Email, hashedPassword, req.FullName)
    if err != nil {
        if strings.Contains(err.Error(), "already exists") {
            slog.WarnContext(ctx, "Service: Registration conflict", "email", req.Email, "error", err.Error())
            return nil, status.Errorf(codes.AlreadyExists, err.Error())
        }
        slog.ErrorContext(ctx, "Service: User creation failed", "email", req.Email, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to register user")
    }

    userInfo, err := s.userRepo.GetUserByID(ctx, createdUser.ID)
    if err != nil {
        slog.ErrorContext(ctx, "Service: Registered but failed to fetch details", "userID", createdUser.ID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "User registered but failed to retrieve details")
    }

    slog.InfoContext(ctx, "Service: User registered successfully", "userID", userInfo.UserId, "email", userInfo.Email)
    return &pb.RegisterResponse{User: userInfo, Message: "User registered successfully"}, nil
}

// Login
func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
    slog.InfoContext(ctx, "Service: Login attempt", "email", req.Email)
    if req.Email == "" || req.Password == "" {
        slog.WarnContext(ctx, "Service: Login failed - missing email or password", "email", req.Email)
        return nil, status.Errorf(codes.InvalidArgument, "Email and password are required")
    }

    userInfo, storedHash, isActive, err := s.userRepo.GetUserByEmail(ctx, req.Email)
    if err != nil {
        slog.WarnContext(ctx, "Service: Login failed - GetUserByEmail", "email", req.Email, "error", err.Error())
        return nil, status.Errorf(codes.Unauthenticated, "Invalid email or password")
    }
    if !isActive {
        slog.WarnContext(ctx, "Service: Login blocked - inactive", "userID", userInfo.UserId, "email", req.Email)
        return nil, status.Errorf(codes.PermissionDenied, "User account is disabled")
    }
    if !checkPasswordHash(req.Password, storedHash) {
        slog.WarnContext(ctx, "Service: Login failed - wrong password", "userID", userInfo.UserId, "email", req.Email)
        return nil, status.Errorf(codes.Unauthenticated, "Invalid email or password")
    }

    accessExp := time.Now().Add(accessTokenExpiryDuration)
    accessClaims := jwt.MapClaims{
        "sub":   userInfo.UserId,
        "email": userInfo.Email,
        "roles": userInfo.Roles,
        "exp":   accessExp.Unix(),
        "iat":   time.Now().Unix(),
        "jti":   uuid.NewString(),
    }
    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    signedAccessToken, err := accessToken.SignedString(s.jwtSecret)
    if err != nil {
        slog.ErrorContext(ctx, "Service: Error signing access token", "userID", userInfo.UserId, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Could not generate access token")
    }

    rawRefreshToken, err := generateSecureRandomToken(32)
    if err != nil {
        slog.ErrorContext(ctx, "Service: Error generating raw refresh token", "userID", userInfo.UserId, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Could not generate refresh token")
    }
    hashedRefreshToken := hashToken(rawRefreshToken)
    refreshExp := time.Now().Add(refreshTokenExpiryDuration)
    parsedUserID, _ := uuid.Parse(userInfo.UserId)

    if err := s.userRepo.StoreRefreshToken(ctx, parsedUserID, hashedRefreshToken, refreshExp); err != nil {
        slog.ErrorContext(ctx, "Service: Failed to store refresh token", "userID", userInfo.UserId, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Could not complete login process (token storage)")
    }
    if err := s.userRepo.UpdateUserLastSignInAt(ctx, parsedUserID); err != nil {
        slog.WarnContext(ctx, "Service: Failed to update last_sign_in_at", "userID", userInfo.UserId, "error", err.Error())
    }

    slog.InfoContext(ctx, "Service: Login successful", "userID", userInfo.UserId, "email", userInfo.Email)
    return &pb.LoginResponse{
        User:         userInfo,
        AccessToken:  signedAccessToken,
        RefreshToken: rawRefreshToken,
        ExpiresIn:    int32(time.Until(accessExp).Seconds()),
    }, nil
}

// ValidateToken
func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
    slog.InfoContext(ctx, "Service: ValidateToken request")
    if req.Token == "" {
        slog.WarnContext(ctx, "Service: ValidateToken failed - token empty")
        return nil, status.Errorf(codes.InvalidArgument, "Token is required")
    }

    token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return s.jwtSecret, nil
    })
    if err != nil {
        slog.WarnContext(ctx, "Service: Token parse/validation failed", "error", err.Error())
        if errors.Is(err, jwt.ErrTokenExpired) {
            return nil, status.Errorf(codes.Unauthenticated, "token is expired")
        }
        return nil, status.Errorf(codes.Unauthenticated, "Invalid access token")
    }

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        userIDStr, okUserID := claims["sub"].(string)
        if !okUserID {
            slog.WarnContext(ctx, "Service: ValidateToken - missing sub claim")
            return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims (sub)")
        }
        userID, err := uuid.Parse(userIDStr)
        if err != nil {
            slog.WarnContext(ctx, "Service: ValidateToken - invalid user_id format", "userID_str", userIDStr, "error", err.Error())
            return nil, status.Errorf(codes.Unauthenticated, "Invalid token claims (user_id format)")
        }

        userInfo, err := s.userRepo.GetUserByID(ctx, userID)
        if err != nil {
            slog.WarnContext(ctx, "Service: ValidateToken - user not found", "userID", userIDStr, "error", err.Error())
            return nil, status.Errorf(codes.Unauthenticated, "User associated with token not found")
        }
        if !userInfo.IsActive {
            slog.WarnContext(ctx, "Service: ValidateToken - inactive account", "userID", userInfo.UserId)
            return nil, status.Errorf(codes.PermissionDenied, "User account is disabled")
        }

        slog.InfoContext(ctx, "Service: Access token validated", "userID", userInfo.UserId, "email", userInfo.Email)
        return &pb.ValidateTokenResponse{User: userInfo}, nil
    }

    slog.WarnContext(ctx, "Service: ValidateToken - invalid token structure")
    return nil, status.Errorf(codes.Unauthenticated, "Invalid access token")
}

// RefreshAccessToken
func (s *AuthServiceServer) RefreshAccessToken(ctx context.Context, req *pb.RefreshAccessTokenRequest) (*pb.LoginResponse, error) {
    slog.InfoContext(ctx, "Service: RefreshAccessToken request")
    if req.RefreshToken == "" {
        slog.WarnContext(ctx, "Service: RefreshAccessToken failed - refresh token empty")
        return nil, status.Errorf(codes.InvalidArgument, "Refresh token is required")
    }

    hashedRefreshToken := hashToken(req.RefreshToken)
    dbToken, err := s.userRepo.GetRefreshTokenByHash(ctx, hashedRefreshToken)
    if err != nil {
        slog.WarnContext(ctx, "Service: Invalid/expired refresh token", "error", err.Error())
        return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired refresh token")
    }

    if err := s.userRepo.RevokeRefreshTokenByHash(ctx, dbToken.TokenHash); err != nil {
        slog.ErrorContext(ctx, "Service: Failed to revoke old refresh token", "userID", dbToken.UserID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to process refresh token rotation")
    }

    userInfo, err := s.userRepo.GetUserByID(ctx, dbToken.UserID)
    if err != nil {
        slog.ErrorContext(ctx, "Service: User for refresh token not found", "userID", dbToken.UserID.String(), "error", err)
        return nil, status.Errorf(codes.Unauthenticated, "User for refresh token is invalid")
    }
    if !userInfo.IsActive {
        slog.WarnContext(ctx, "Service: Refresh token user not active", "userID", dbToken.UserID.String())
        return nil, status.Errorf(codes.PermissionDenied, "User account (for refresh token) is disabled")
    }

    accessExp := time.Now().Add(accessTokenExpiryDuration)
    accessClaims := jwt.MapClaims{
        "sub":   userInfo.UserId,
        "email": userInfo.Email,
        "roles": userInfo.Roles,
        "exp":   accessExp.Unix(),
        "iat":   time.Now().Unix(),
        "jti":   uuid.NewString(),
    }
    newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    signedNewAccessToken, errToken := newAccessToken.SignedString(s.jwtSecret)
    if errToken != nil {
        slog.ErrorContext(ctx, "Service: Error signing new access token", "userID", userInfo.UserId, "error", errToken.Error())
        return nil, status.Errorf(codes.Internal, "Could not generate new access token")
    }

    newRawRefreshToken := uuid.NewString()
    newHashedRefreshToken := hashToken(newRawRefreshToken)
    newRefreshExp := time.Now().Add(refreshTokenExpiryDuration)
    if errStore := s.userRepo.StoreRefreshToken(ctx, dbToken.UserID, newHashedRefreshToken, newRefreshExp); errStore != nil {
        slog.ErrorContext(ctx, "Service: Failed to store new refresh token", "userID", dbToken.UserID.String(), "error", errStore.Error())
        return nil, status.Errorf(codes.Internal, "Failed to complete token refresh, please log in again")
    }

    slog.InfoContext(ctx, "Service: Access token refreshed", "userID", userInfo.UserId)
    return &pb.LoginResponse{
        User:         userInfo,
        AccessToken:  signedNewAccessToken,
        RefreshToken: newRawRefreshToken,
        ExpiresIn:    int32(time.Until(accessExp).Seconds()),
    }, nil
}

// Logout
func (s *AuthServiceServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
    slog.InfoContext(ctx, "Service: Logout request")
    if req.RefreshToken == "" {
        slog.InfoContext(ctx, "Service: Logout (no refresh token provided)")
        return &pb.LogoutResponse{Message: "Logged out (client should clear tokens)."}, nil
    }

    hashedRefreshToken := hashToken(req.RefreshToken)
    err := s.userRepo.RevokeRefreshTokenByHash(ctx, hashedRefreshToken)
    if err != nil {
        slog.ErrorContext(ctx, "Service: Error revoking refresh token on logout", "error", err.Error())
        return &pb.LogoutResponse{Message: "Logout processed, but server-side token revocation encountered an issue."}, nil
    }

    slog.InfoContext(ctx, "Service: Refresh token revoked on logout")
    return &pb.LogoutResponse{Message: "Successfully logged out and refresh token revoked."}, nil
}

// RequestPasswordReset
func (s *AuthServiceServer) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetRequest) (*pb.RequestPasswordResetResponse, error) {
    slog.InfoContext(ctx, "Service: RequestPasswordReset request", "email", req.Email)
    if req.Email == "" {
        slog.WarnContext(ctx, "Service: RequestPasswordReset failed - email required")
        return nil, status.Errorf(codes.InvalidArgument, "Email is required")
    }

    userInfo, _, isActive, err := s.userRepo.GetUserByEmail(ctx, req.Email)
    if err != nil || (userInfo != nil && !isActive) {
        if err != nil && !strings.Contains(err.Error(), "not found") {
            slog.ErrorContext(ctx, "Service: DB error during password reset request", "email", req.Email, "error", err.Error())
        } else if userInfo != nil && !isActive {
            slog.WarnContext(ctx, "Service: Password reset for inactive user", "email", req.Email, "userID", userInfo.UserId)
        } else {
            slog.InfoContext(ctx, "Service: Password reset for non-existent email", "email", req.Email)
        }
        return &pb.RequestPasswordResetResponse{
            Message:          "If an account with that email exists, a password reset link has been sent.",
            ExpiresInSeconds: int32(passwordResetTokenExpiry.Seconds()),
        }, nil
    }

    parsedUserID, _ := uuid.Parse(userInfo.UserId)
    rawResetToken, err := generateSecureRandomToken(passwordResetTokenBytesLength)
    if err != nil {
        slog.ErrorContext(ctx, "Service: Failed to generate password reset token", "userID", parsedUserID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to initiate password reset")
    }
    hashedResetToken := hashToken(rawResetToken)
    expiresAt := time.Now().Add(passwordResetTokenExpiry)

    if err := s.userRepo.StorePasswordResetToken(ctx, parsedUserID, hashedResetToken, expiresAt); err != nil {
        slog.ErrorContext(ctx, "Service: Failed to store password reset token", "userID", parsedUserID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to initiate password reset process")
    }

    resetLink := fmt.Sprintf("https://voya.go/reset-password?token=%s", rawResetToken)
    slog.InfoContext(ctx, "MOCK_EMAIL: Password reset email (would be sent)",
        "to", userInfo.Email,
        "subject", "VoyaGo Password Reset",
        "reset_link_for_testing_only", resetLink,
        "raw_token_for_testing_only", rawResetToken,
    )

    return &pb.RequestPasswordResetResponse{
        Message:          "If an account with that email exists, a password reset link has been sent.",
        ExpiresInSeconds: int32(passwordResetTokenExpiry.Seconds()),
    }, nil
}

// ConfirmPasswordReset
func (s *AuthServiceServer) ConfirmPasswordReset(ctx context.Context, req *pb.ConfirmPasswordResetRequest) (*pb.ConfirmPasswordResetResponse, error) {
    slog.InfoContext(ctx, "Service: ConfirmPasswordReset request")
    if req.ResetToken == "" || len(req.NewPassword) < 8 {
        slog.WarnContext(ctx, "Service: ConfirmPasswordReset failed - invalid token or short password")
        return nil, status.Errorf(codes.InvalidArgument, "Valid reset token and new password (min 8 chars) are required")
    }

    hashedResetToken := hashToken(req.ResetToken)
    dbResetToken, err := s.userRepo.GetValidPasswordResetTokenByHash(ctx, hashedResetToken)
    if err != nil {
        slog.WarnContext(ctx, "Service: ConfirmPasswordReset - invalid/expired token", "error", err.Error())
        return nil, status.Errorf(codes.InvalidArgument, "Invalid or expired reset token")
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
        slog.ErrorContext(ctx, "Service: ConfirmPasswordReset - failed to mark reset token as used", "userID", dbResetToken.UserID.String(), "error", err.Error())
    }

    if err := s.userRepo.RevokeAllRefreshTokensForUser(ctx, dbResetToken.UserID); err != nil {
        slog.WarnContext(ctx, "Service: ConfirmPasswordReset - failed to revoke all refresh tokens", "userID", dbResetToken.UserID.String(), "error", err.Error())
    }

    slog.InfoContext(ctx, "Service: Password updated via reset token", "userID", dbResetToken.UserID.String())
    return &pb.ConfirmPasswordResetResponse{
        Message: "Password successfully updated. You can now log in with your new password.",
    }, nil
}

// ChangePassword
func (s *AuthServiceServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
    slog.InfoContext(ctx, "Service: ChangePassword request")
    if req.AccessToken == "" {
        slog.WarnContext(ctx, "Service: ChangePassword failed - access token required")
        return nil, status.Errorf(codes.InvalidArgument, "Access token is required")
    }
    if req.OldPassword == "" {
        slog.WarnContext(ctx, "Service: ChangePassword failed - old password required")
        return nil, status.Errorf(codes.InvalidArgument, "Old password is required")
    }
    if len(req.NewPassword) < 8 {
        slog.WarnContext(ctx, "Service: ChangePassword failed - new password too short")
        return nil, status.Errorf(codes.InvalidArgument, "New password must be at least 8 characters long")
    }
    if req.OldPassword == req.NewPassword {
        slog.WarnContext(ctx, "Service: ChangePassword failed - new password same as old")
        return nil, status.Errorf(codes.InvalidArgument, "New password cannot be the same as the old password")
    }

    validateRes, err := s.ValidateToken(ctx, &pb.ValidateTokenRequest{Token: req.AccessToken})
    if err != nil {
        slog.WarnContext(ctx, "Service: ChangePassword - invalid access token", "error", err)
        return nil, err
    }
    userInfo := validateRes.User
    if userInfo == nil {
        slog.ErrorContext(ctx, "Service: ChangePassword - UserInfo nil")
        return nil, status.Errorf(codes.Internal, "Failed to retrieve user information")
    }
    userID, errParse := uuid.Parse(userInfo.UserId)
    if errParse != nil {
        slog.ErrorContext(ctx, "Service: ChangePassword - failed to parse UserID", "userID_str", userInfo.UserId, "error", errParse.Error())
        return nil, status.Errorf(codes.Internal, "Internal server error processing user ID")
    }

    _, storedHash, isActive, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
    if err != nil {
        slog.ErrorContext(ctx, "Service: ChangePassword - could not fetch user", "userID", userID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to process your request")
    }
    if !isActive {
        slog.WarnContext(ctx, "Service: ChangePassword failed - inactive account", "userID", userID.String())
        return nil, status.Errorf(codes.PermissionDenied, "User account is disabled")
    }

    if !checkPasswordHash(req.OldPassword, storedHash) {
        slog.WarnContext(ctx, "Service: ChangePassword failed - incorrect old password", "userID", userID.String())
        return nil, status.Errorf(codes.Unauthenticated, "Incorrect old password")
    }

    newPasswordHash, err := hashPassword(req.NewPassword)
    if err != nil {
        slog.ErrorContext(ctx, "Service: ChangePassword - error hashing new password", "userID", userID.String(), "error", err.Error())
       	return nil, status.Errorf(codes.Internal, "Failed to process new password")
    }

    if err := s.userRepo.UpdateUserPassword(ctx, userID, newPasswordHash); err != nil {
        slog.ErrorContext(ctx, "Service: ChangePassword - error updating password", "userID", userID.String(), "error", err.Error()) 
        return nil, status.Errorf(codes.Internal, "Failed to update password")
    }

    if err := s.userRepo.RevokeAllRefreshTokensForUser(ctx, userID); err != nil {
        slog.WarnContext(ctx, "Service: ChangePassword - failed to revoke refresh tokens", "userID", userID.String(), "error", err.Error())
    }

    slog.InfoContext(ctx, "Service: Password changed successfully by user", "userID", userID.String())
    return &pb.ChangePasswordResponse{Message: "Password changed successfully."}, nil
}

// RequestEmailVerification
func (s *AuthServiceServer) RequestEmailVerification(ctx context.Context, req *pb.RequestEmailVerificationRequest) (*pb.RequestEmailVerificationResponse, error) {
    slog.InfoContext(ctx, "Service: RequestEmailVerification request")
    if req.AccessToken == "" {
        slog.WarnContext(ctx, "Service: RequestEmailVerification failed - access token required")
        return nil, status.Errorf(codes.InvalidArgument, "Access token is required")
    }

    validateRes, err := s.ValidateToken(ctx, &pb.ValidateTokenRequest{Token: req.AccessToken})
    if err != nil {
        slog.WarnContext(ctx, "Service: RequestEmailVerification failed - invalid access token", "error", err)
        return nil, err
    }
    userInfo := validateRes.User
    if userInfo.EmailVerified {
        slog.InfoContext(ctx, "Service: Email already verified", "userID", userInfo.UserId, "email", userInfo.Email)
        return &pb.RequestEmailVerificationResponse{Message: "Your email address is already verified."}, nil
    }

    parsedUserID, errParse := uuid.Parse(userInfo.UserId)
    if errParse != nil {
        slog.ErrorContext(ctx, "Service: RequestEmailVerification - failed to parse UserID", "userID_str", userInfo.UserId, "error", errParse.Error())
        return nil, status.Errorf(codes.Internal, "Internal server error processing user ID")
    }

    rawVerificationToken, err := generateSecureRandomToken(emailVerificationTokenBytesLength)
    if err != nil {
        slog.ErrorContext(ctx, "Service: RequestEmailVerification - failed to generate token", "userID", parsedUserID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to initiate email verification")
    }
    hashedVerificationToken := hashToken(rawVerificationToken)
    expiresAt := time.Now().Add(emailVerificationTokenExpiry)

    if err := s.userRepo.StoreEmailVerificationToken(ctx, parsedUserID, userInfo.Email, hashedVerificationToken, expiresAt); err != nil {
        slog.ErrorContext(ctx, "Service: RequestEmailVerification - failed to store token", "userID", parsedUserID.String(), "email", userInfo.Email, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to initiate email verification process")
    }

    verificationLink := fmt.Sprintf("https://voya.go/verify-email?token=%s", rawVerificationToken)
    slog.InfoContext(ctx, "MOCK_EMAIL: Email verification",
        "to", userInfo.Email,
        "subject", "VoyaGo Email Verification",
        "verification_link_for_debug", verificationLink,
        "raw_token_for_debug", rawVerificationToken,
    )

    slog.InfoContext(ctx, "Service: Email verification token generated", "userID", userInfo.UserId, "email", userInfo.Email)
    return &pb.RequestEmailVerificationResponse{
        Message:          "A verification link has been sent to your email address.",
        ExpiresInSeconds: int32(emailVerificationTokenExpiry.Seconds()),
    }, nil
}

// ConfirmEmailVerification
func (s *AuthServiceServer) ConfirmEmailVerification(ctx context.Context, req *pb.ConfirmEmailVerificationRequest) (*pb.ConfirmEmailVerificationResponse, error) {
    slog.InfoContext(ctx, "Service: ConfirmEmailVerification request")
    if req.VerificationToken == "" {
        slog.WarnContext(ctx, "Service: ConfirmEmailVerification failed - token required")
        return nil, status.Errorf(codes.InvalidArgument, "Verification token is required")
    }

    hashedVerificationToken := hashToken(req.VerificationToken)
    dbVerificationToken, err := s.userRepo.GetValidEmailVerificationTokenByHash(ctx, hashedVerificationToken)
    if err != nil {
        slog.WarnContext(ctx, "Service: ConfirmEmailVerification - invalid/expired token", "error", err.Error())
        return nil, status.Errorf(codes.InvalidArgument, "Invalid, expired, or already used verification token")
    }

    if err := s.userRepo.MarkUserEmailAsVerified(ctx, dbVerificationToken.UserID); err != nil {
        slog.ErrorContext(ctx, "Service: ConfirmEmailVerification - error marking email verified", "userID", dbVerificationToken.UserID.String(), "email", dbVerificationToken.Email, "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to verify email address")
    }

    if err := s.userRepo.MarkEmailVerificationTokenAsUsed(ctx, dbVerificationToken.TokenHash); err != nil {
        slog.ErrorContext(ctx, "Service: ConfirmEmailVerification - failed to mark token as used", "userID", dbVerificationToken.UserID.String(), "tokenHash", dbVerificationToken.TokenHash, "error", err.Error())
    }

    updatedUserInfo, err := s.userRepo.GetUserByID(ctx, dbVerificationToken.UserID)
    if err != nil {
        slog.ErrorContext(ctx, "Service: ConfirmEmailVerification - failed to fetch updated user info", "userID", dbVerificationToken.UserID.String(), "error", err.Error())
        return &pb.ConfirmEmailVerificationResponse{
            Message: "Email successfully verified. User details could not be retrieved.",
        }, nil
    }

    slog.InfoContext(ctx, "Service: Email successfully verified", "userID", dbVerificationToken.UserID.String(), "email", dbVerificationToken.Email)
    return &pb.ConfirmEmailVerificationResponse{
        Message: "Email successfully verified.",
        User:    updatedUserInfo,
    }, nil
}

// UpdateUserMetadata
func (s *AuthServiceServer) UpdateUserMetadata(ctx context.Context, req *pb.UpdateUserMetadataRequest) (*pb.UpdateUserMetadataResponse, error) {
    slog.InfoContext(ctx, "Service: UpdateUserMetadata request", "access_token_present", req.AccessToken != "", "full_name_to_update", req.FullName)
    if req.AccessToken == "" {
        slog.WarnContext(ctx, "Service: UpdateUserMetadata failed - access token required")
        return nil, status.Errorf(codes.InvalidArgument, "Access token is required")
    }

    validateRes, err := s.ValidateToken(ctx, &pb.ValidateTokenRequest{Token: req.AccessToken})
    if err != nil {
        slog.WarnContext(ctx, "Service: UpdateUserMetadata failed - invalid access token", "error", err)
        return nil, err
    }
    userInfo := validateRes.User
    if userInfo == nil {
        slog.ErrorContext(ctx, "Service: UpdateUserMetadata - UserInfo nil")
        return nil, status.Errorf(codes.Internal, "Failed to retrieve user information")
    }
    parsedUserID, errParse := uuid.Parse(userInfo.UserId)
    if errParse != nil {
        slog.ErrorContext(ctx, "Service: UpdateUserMetadata - failed to parse UserID", "userID_str", userInfo.UserId, "error", errParse.Error())
        return nil, status.Errorf(codes.Internal, "Internal server error processing user ID")
    }

    if err := s.userRepo.UpdateUserFullName(ctx, parsedUserID, req.FullName); err != nil {
        slog.ErrorContext(ctx, "Service: UpdateUserMetadata failed - error updating full_name", "userID", parsedUserID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "Failed to update user metadata")
    }

    updatedUserInfo, err := s.userRepo.GetUserByID(ctx, parsedUserID)
    if err != nil {
        slog.ErrorContext(ctx, "Service: UpdateUserMetadata - updated but failed to retrieve user data", "userID", parsedUserID.String(), "error", err.Error())
        return nil, status.Errorf(codes.Internal, "User metadata updated, but failed to retrieve complete user data")
    }

    slog.InfoContext(ctx, "Service: User metadata updated", "userID", userInfo.UserId, "new_full_name", req.FullName)
    return &pb.UpdateUserMetadataResponse{User: updatedUserInfo}, nil
}
