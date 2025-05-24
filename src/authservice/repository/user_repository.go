package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	pb "github.com/voyalis/voyago-base/src/authservice/genproto"
)

const (
	PassengerRoleID = 1
)

type User struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  string
	FullName      sql.NullString
	IsActive      bool
	EmailVerified bool
	LastSignInAt  sql.NullTime
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type RefreshToken struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	TokenHash     string
	ParentID      uuid.NullUUID
	Revoked       bool
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

type PasswordResetToken struct {
	TokenHash string    // PK
	UserID    uuid.UUID
	ExpiresAt time.Time
	CreatedAt time.Time
	Consumed  bool
}



// UserRepoInterface, UserRepo'nun implemente edeceği metotları tanımlar.
// Bu interface, service katmanının repository'ye olan bağımlılığını soyutlar.
type UserRepoInterface interface {
	CreateUser(ctx context.Context, email, passwordHash, fullName string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string /*passwordHash*/, bool /*isActive*/, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error)
	StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error
	RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error
	UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error
	StorePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	GetValidPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error)
	MarkPasswordResetTokenAsUsed(ctx context.Context, tokenHash string) error
	UpdateUserPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error
	
}

type UserRepo struct {
	db *sql.DB
}

// NewUserRepo, UserRepoInterface'i implemente eden yeni bir UserRepo örneği oluşturur.
func NewUserRepo(database *sql.DB) UserRepoInterface {
	return &UserRepo{db: database}
}

// UserRepo struct'ının UserRepoInterface'i implemente ettiğinden emin olalım.
var _ UserRepoInterface = (*UserRepo)(nil)

// Metot implementasyonları (içerikleri bir önceki mesajınızdaki gibi slog kullanarak)

func (r *UserRepo) CreateUser(ctx context.Context, email, passwordHash, fullName string) (*User, error) {
	targetDB := r.db
	var newUser User
	var err error
	tx, errTx := targetDB.BeginTx(ctx, nil)
	if errTx != nil {
		slog.ErrorContext(ctx, "Repository: Failed to begin transaction", "error", errTx)
		return nil, fmt.Errorf("could not start transaction: %w", errTx)
	}
	defer func() {
		if p := recover(); p != nil { _ = tx.Rollback(); slog.ErrorContext(ctx, "Repository: Transaction recovered from panic", "panic", p); panic(p)
		} else if err != nil { slog.WarnContext(ctx, "Repository: Rolling back transaction", "error", err); _ = tx.Rollback()
		} else { err = tx.Commit(); if err != nil { slog.ErrorContext(ctx, "Repository: Failed to commit transaction", "error", err) }}
	}()
	userQuery := `INSERT INTO auth.users (email, password_hash, full_name, is_active, email_verified) VALUES ($1, $2, $3, TRUE, FALSE) RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at`
	var sqlFullName sql.NullString
	if fullName != "" { sqlFullName = sql.NullString{String: fullName, Valid: true} }
	err = tx.QueryRowContext(ctx, userQuery, email, passwordHash, sqlFullName).Scan(
		&newUser.ID, &newUser.Email, &newUser.PasswordHash, &newUser.FullName,
		&newUser.IsActive, &newUser.EmailVerified, &newUser.CreatedAt, &newUser.UpdatedAt, &newUser.LastSignInAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" { err = fmt.Errorf("email '%s' already exists", email); slog.WarnContext(ctx, "Repository: User creation conflict", "email", email, "original_error_code", pgErr.Code); return nil, err }
		slog.ErrorContext(ctx, "Repository: Error inserting user", "email", email, "error", err); err = fmt.Errorf("could not create user: %w", err); return nil, err
	}
	roleQuery := `INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, roleQuery, newUser.ID, PassengerRoleID)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error assigning default role", "userID", newUser.ID.String(), "error", err); err = fmt.Errorf("could not assign default role: %w", err); return nil, err }
	slog.InfoContext(ctx, "Repository: User created", "userID", newUser.ID.String(), "email", newUser.Email)
	return &newUser, err
}

func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error) {
	targetDB := r.db; var userID uuid.UUID; var storedPasswordHash string; var userFullName sql.NullString; var isActive, emailVerified bool
	userQuery := `SELECT id, password_hash, full_name, is_active, email_verified FROM auth.users WHERE email = $1`
	err := targetDB.QueryRowContext(ctx, userQuery, email).Scan(&userID, &storedPasswordHash, &userFullName, &isActive, &emailVerified)
	if err != nil {
		if err == sql.ErrNoRows { slog.DebugContext(ctx, "Repository: User not found by email", "email", email); return nil, "", false, fmt.Errorf("user with email '%s' not found", email) }
		slog.ErrorContext(ctx, "Repository: Error fetching user by email", "email", email, "error", err); return nil, "", false, fmt.Errorf("database error: %w", err)
	}
	var roles []string
	rolesQuery := `SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`
	rows, err := targetDB.QueryContext(ctx, rolesQuery, userID)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error fetching roles", "userID", userID.String(), "error", err); return nil, "", false, fmt.Errorf("db error fetching roles: %w", err) }
	defer rows.Close()
	for rows.Next() { var roleName string; if err = rows.Scan(&roleName); err != nil { slog.ErrorContext(ctx, "Repository: Error scanning role", "userID", userID.String(), "error", err); return nil, "", false, fmt.Errorf("db error scanning role: %w", err) }; roles = append(roles, roleName) }
	if err = rows.Err(); err != nil { slog.ErrorContext(ctx, "Repository: Error after iterating roles", "userID", userID.String(), "error", err); return nil, "", false, fmt.Errorf("db error iterating roles: %w", err) }
	if len(roles) == 0 { slog.WarnContext(ctx, "Repository: No roles for user", "userID", userID.String()); roles = append(roles, "passenger")}
	userInfo := &pb.UserInfo{UserId: userID.String(), Email: email, FullName: userFullName.String, Roles: roles, IsActive: isActive, EmailVerified: emailVerified}
	slog.DebugContext(ctx, "Repository: User fetched by email", "userID", userID.String(), "isActive", isActive)
	return userInfo, storedPasswordHash, isActive, nil
}

func (r *UserRepo) GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error) {
	targetDB := r.db; var userEmail string; var userFullName sql.NullString; var isActive, emailVerified bool
	userQuery := `SELECT email, full_name, is_active, email_verified FROM auth.users WHERE id = $1`
	err := targetDB.QueryRowContext(ctx, userQuery, userID).Scan(&userEmail, &userFullName, &isActive, &emailVerified)
	if err != nil {
		if err == sql.ErrNoRows { slog.DebugContext(ctx, "Repository: User not found by ID", "userID", userID.String()); return nil, fmt.Errorf("user with ID '%s' not found", userID.String()) }
		slog.ErrorContext(ctx, "Repository: Error fetching user by ID", "userID", userID.String(), "error", err); return nil, fmt.Errorf("db error fetching user by ID: %w", err)
	}
	var roles []string
	rolesQuery := `SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`
	rows, err := targetDB.QueryContext(ctx, rolesQuery, userID)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error fetching roles by ID", "userID", userID.String(), "error", err); return nil, fmt.Errorf("db error fetching roles by ID: %w", err) }
	defer rows.Close()
	for rows.Next() { var roleName string; if err = rows.Scan(&roleName); err != nil { slog.ErrorContext(ctx, "Repository: Error scanning role by ID", "userID", userID.String(), "error", err); return nil, fmt.Errorf("db error scanning role by ID: %w", err) }; roles = append(roles, roleName) }
	if err = rows.Err(); err != nil { slog.ErrorContext(ctx, "Repository: Error after iterating roles by ID", "userID", userID.String(), "error", err); return nil, fmt.Errorf("db error iterating roles by ID: %w", err) }
	if len(roles) == 0 { slog.WarnContext(ctx, "Repository: No roles for user by ID", "userID", userID.String()); roles = append(roles, "passenger")}
	userInfo := &pb.UserInfo{UserId: userID.String(), Email: userEmail, FullName: userFullName.String, Roles: roles, IsActive: isActive, EmailVerified: emailVerified}
	slog.DebugContext(ctx, "Repository: User fetched by ID", "userID", userID.String())
	return userInfo, nil
}

func (r *UserRepo) StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	query := `INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`
	_, err := r.db.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" { slog.WarnContext(ctx, "Repository: Refresh token hash conflict", "userID", userID.String()); return fmt.Errorf("refresh token hash already exists") }
		slog.ErrorContext(ctx, "Repository: Error storing refresh token", "userID", userID.String(), "error", err); return fmt.Errorf("could not store refresh token: %w", err)
	}
	slog.InfoContext(ctx, "Repository: Refresh token stored", "userID", userID.String())
	return nil
}

func (r *UserRepo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var rt RefreshToken
	query := `SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM auth.refresh_tokens WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.Revoked, &rt.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows { slog.DebugContext(ctx, "Repository: Refresh token not found by hash"); return nil, fmt.Errorf("refresh token not found, expired, or revoked") }
		slog.ErrorContext(ctx, "Repository: Error getting refresh token by hash", "error", err); return nil, fmt.Errorf("could not get refresh token: %w", err)
	}
	slog.DebugContext(ctx, "Repository: Refresh token fetched by hash", "userID", rt.UserID.String())
	return &rt, nil
}

func (r *UserRepo) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error {
	query := `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND revoked = FALSE`
	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error revoking refresh token", "error", err); return fmt.Errorf("could not revoke refresh token: %w", err) }
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 { slog.WarnContext(ctx, "Repository: No active refresh token found to revoke")
	} else { slog.InfoContext(ctx, "Repository: Refresh token revoked") }
	return nil
}

func (r *UserRepo) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error revoking all refresh tokens", "userID", userID.String(), "error", err); return fmt.Errorf("could not revoke all refresh tokens: %w", err) }
	slog.InfoContext(ctx, "Repository: All active refresh tokens revoked", "userID", userID.String())
	return nil
}

func (r *UserRepo) UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE auth.users SET last_sign_in_at = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error updating last_sign_in_at", "userID", userID.String(), "error", err); return fmt.Errorf("could not update last_sign_in_at: %w", err) }
	slog.InfoContext(ctx, "Repository: last_sign_in_at updated", "userID", userID.String())
	return nil
}

func (r *UserRepo) StorePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at, consumed)
		VALUES ($1, $2, $3, FALSE)
		ON CONFLICT (token_hash) DO UPDATE SET 
			user_id = EXCLUDED.user_id,
			expires_at = EXCLUDED.expires_at,
			consumed = FALSE,
			created_at = NOW()` // Veya ON CONFLICT DO NOTHING de olabilir, uygulamanın mantığına göre
	_, err := r.db.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error storing password reset token", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not store password reset token: %w", err)
	}
	slog.InfoContext(ctx, "Repository: Password reset token stored", "userID", userID.String(), "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	return nil
}

func (r *UserRepo) GetValidPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	var prt PasswordResetToken
	query := `
		SELECT token_hash, user_id, expires_at, created_at, consumed
		FROM auth.password_reset_tokens
		WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&prt.TokenHash,
		&prt.UserID,
		&prt.ExpiresAt,
		&prt.CreatedAt,
		&prt.Consumed,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: Password reset token not found, expired, or already consumed", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
			return nil, fmt.Errorf("password reset token not found, expired, or consumed")
		}
		slog.ErrorContext(ctx, "Repository: Error getting password reset token by hash", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return nil, fmt.Errorf("could not get password reset token: %w", err)
	}
	slog.DebugContext(ctx, "Repository: Valid password reset token fetched by hash", "userID", prt.UserID.String())
	return &prt, nil
}

func (r *UserRepo) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenHash string) error {
	query := `UPDATE auth.password_reset_tokens SET consumed = TRUE WHERE token_hash = $1 AND consumed = FALSE`
	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error marking password reset token as used", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return fmt.Errorf("could not mark password reset token as used: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: No active password reset token found to mark as used", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
		// Bu bir hata olabilir (beklenmedik durum) veya token zaten kullanılmış/süresi dolmuş olabilir.
		// return fmt.Errorf("no active password reset token found to mark as used") // İsteğe bağlı
	} else {
		slog.InfoContext(ctx, "Repository: Password reset token marked as used", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	}
	return nil
}

func (r *UserRepo) UpdateUserPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	query := `UPDATE auth.users SET password_hash = $1, updated_at = NOW() WHERE id = $2`
	result, err := r.db.ExecContext(ctx, query, newPasswordHash, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error updating user password", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not update user password: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: User not found to update password (or password already same - unlikely with hash)", "userID", userID.String())
		return fmt.Errorf("user not found to update password, or no change needed")
	}
	slog.InfoContext(ctx, "Repository: User password updated successfully", "userID", userID.String())
	return nil
}

// min helper (eğer bu pakette de gerekirse, yoksa kaldırılabilir)
// func min(a, b int) int { if a < b { return a }; return b }