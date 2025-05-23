package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog" // Değişti
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
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	ParentID   uuid.NullUUID
	Revoked    bool
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(database *sql.DB) *UserRepo {
	return &UserRepo{db: database}
}

func (r *UserRepo) CreateUser(ctx context.Context, email, passwordHash, fullName string) (*User, error) {
	var newUser User
	var err error

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Failed to begin transaction", "error", err)
		return nil, fmt.Errorf("could not start transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			slog.ErrorContext(ctx, "Repository: Transaction recovered from panic and rolled back", "panic", p)
			panic(p)
		} else if err != nil {
			slog.WarnContext(ctx, "Repository: Rolling back transaction due to error", "error", err)
			_ = tx.Rollback()
		} else {
			err = tx.Commit()
			if err != nil {
				slog.ErrorContext(ctx, "Repository: Failed to commit transaction", "error", err)
				// err burada set edildiği için fonksiyon bu hatayı dönecek
			}
		}
	}()

	userQuery := `
		INSERT INTO auth.users (email, password_hash, full_name, is_active, email_verified)
		VALUES ($1, $2, $3, TRUE, FALSE)
		RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at`

	var sqlFullName sql.NullString
	if fullName != "" {
		sqlFullName = sql.NullString{String: fullName, Valid: true}
	}

	err = tx.QueryRowContext(ctx, userQuery, email, passwordHash, sqlFullName).Scan(
		&newUser.ID, &newUser.Email, &newUser.PasswordHash, &newUser.FullName,
		&newUser.IsActive, &newUser.EmailVerified, &newUser.CreatedAt, &newUser.UpdatedAt, &newUser.LastSignInAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			err = fmt.Errorf("email '%s' already exists", email)
			slog.WarnContext(ctx, "Repository: User creation conflict", "email", email, "error", err)
			return nil, err
		}
		slog.ErrorContext(ctx, "Repository: Error inserting user into database", "email", email, "error", err)
		err = fmt.Errorf("could not create user: %w", err)
		return nil, err
	}

	roleQuery := `INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2)
	              ON CONFLICT (user_id, role_id) DO NOTHING`
	_, err = tx.ExecContext(ctx, roleQuery, newUser.ID, PassengerRoleID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error assigning default role", "userID", newUser.ID.String(), "error", err)
		err = fmt.Errorf("could not assign default role: %w", err)
		return nil, err
	}

	slog.InfoContext(ctx, "Repository: User created successfully", "userID", newUser.ID.String(), "email", newUser.Email)
	return &newUser, err // Defer'deki commit başarılıysa err nil olacak
}

func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error) {
	targetDB := r.db
	var userID uuid.UUID
	var storedPasswordHash string
	var userFullName sql.NullString
	var isActive, emailVerified bool

	userQuery := `SELECT id, password_hash, full_name, is_active, email_verified FROM auth.users WHERE email = $1`
	err := targetDB.QueryRowContext(ctx, userQuery, email).Scan(
		&userID, &storedPasswordHash, &userFullName, &isActive, &emailVerified,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: User not found by email", "email", email)
			return nil, "", false, fmt.Errorf("user with email '%s' not found", email)
		}
		slog.ErrorContext(ctx, "Repository: Error fetching user by email", "email", email, "error", err)
		return nil, "", false, fmt.Errorf("database error when fetching user: %w", err)
	}

	var roles []string
	rolesQuery := `SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`
	rows, err := targetDB.QueryContext(ctx, rolesQuery, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error fetching roles for user", "userID", userID.String(), "error", err)
		return nil, "", false, fmt.Errorf("database error when fetching roles: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var roleName string
		if err := rows.Scan(&roleName); err != nil {
			slog.ErrorContext(ctx, "Repository: Error scanning role name", "userID", userID.String(), "error", err)
			return nil, "", false, fmt.Errorf("database error scanning role: %w", err)
		}
		roles = append(roles, roleName)
	}
	if err := rows.Err(); err != nil {
		slog.ErrorContext(ctx, "Repository: Error after iterating roles", "userID", userID.String(), "error", err)
		return nil, "", false, fmt.Errorf("database error iterating roles: %w", err)
	}
	if len(roles) == 0 {
		slog.WarnContext(ctx, "Repository: No roles found for user, assigning default 'passenger' for UserInfo.", "userID", userID.String())
		roles = append(roles, "passenger")
	}

	userInfo := &pb.UserInfo{
		UserId:        userID.String(),
		Email:         email,
		FullName:      userFullName.String,
		Roles:         roles,
		IsActive:      isActive,
		EmailVerified: emailVerified,
	}
	slog.DebugContext(ctx, "Repository: User fetched by email successfully", "userID", userID.String(), "email", email)
	return userInfo, storedPasswordHash, isActive, nil
}

func (r *UserRepo) GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error) {
	targetDB := r.db
	var userEmail string
	var userFullName sql.NullString
	var isActive, emailVerified bool

	userQuery := `SELECT email, full_name, is_active, email_verified FROM auth.users WHERE id = $1`
	err := targetDB.QueryRowContext(ctx, userQuery, userID).Scan(
		&userEmail, &userFullName, &isActive, &emailVerified,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: User not found by ID", "userID", userID.String())
			return nil, fmt.Errorf("user with ID '%s' not found", userID.String())
		}
		slog.ErrorContext(ctx, "Repository: Error fetching user by ID", "userID", userID.String(), "error", err)
		return nil, fmt.Errorf("database error when fetching user by ID: %w", err)
	}

	var roles []string
	rolesQuery := `SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`
	rows, err := targetDB.QueryContext(ctx, rolesQuery, userID)
	if err != nil { slog.ErrorContext(ctx, "Repository: Error fetching roles for user", "userID", userID.String(), "error", err); return nil, fmt.Errorf("database error when fetching roles: %w", err) }
	defer rows.Close()
	for rows.Next() { var roleName string; if errR := rows.Scan(&roleName); errR != nil { slog.ErrorContext(ctx, "Repository: Error scanning role name", "userID", userID.String(), "error", errR); return nil, fmt.Errorf("database error scanning role: %w", errR) }; roles = append(roles, roleName) }
	if errR := rows.Err(); errR != nil { slog.ErrorContext(ctx, "Repository: Error after iterating roles", "userID", userID.String(), "error", errR); return nil, fmt.Errorf("database error iterating roles: %w", errR) }
	if len(roles) == 0 { slog.WarnContext(ctx, "Repository: No roles found for user, assigning default 'passenger' for UserInfo.", "userID", userID.String()); roles = append(roles, "passenger") }

	userInfo := &pb.UserInfo{
		UserId:   userID.String(),
		Email:    userEmail,
		FullName: userFullName.String,
		Roles:    roles,
		IsActive: isActive,
		EmailVerified: emailVerified,
	}
	slog.DebugContext(ctx, "Repository: User fetched by ID successfully", "userID", userID.String())
	return userInfo, nil
}

func (r *UserRepo) StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	query := `INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`
	_, err := r.db.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			slog.WarnContext(ctx, "Repository: Refresh token hash already exists or collision", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "userID", userID.String(), "error", err)
			return fmt.Errorf("refresh token hash already exists")
		}
		slog.ErrorContext(ctx, "Repository: Error storing refresh token", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not store refresh token: %w", err)
	}
	slog.InfoContext(ctx, "Repository: Refresh token stored successfully", "userID", userID.String(), "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	return nil
}

func (r *UserRepo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var rt RefreshToken
	query := `SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM auth.refresh_tokens WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.Revoked, &rt.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: Refresh token not found, expired, or revoked", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
			return nil, fmt.Errorf("refresh token not found, expired, or revoked")
		}
		slog.ErrorContext(ctx, "Repository: Error getting refresh token by hash", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return nil, fmt.Errorf("could not get refresh token: %w", err)
	}
	slog.DebugContext(ctx, "Repository: Refresh token fetched by hash successfully", "userID", rt.UserID.String(), "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	return &rt, nil
}

func (r *UserRepo) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error {
	query := `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND revoked = FALSE`
	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error revoking refresh token by hash", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return fmt.Errorf("could not revoke refresh token: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: No refresh token found to revoke or already revoked", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	} else {
		slog.InfoContext(ctx, "Repository: Refresh token revoked successfully", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	}
	return nil
}

func (r *UserRepo) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE auth.refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error revoking all refresh tokens for user", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not revoke all refresh tokens for user: %w", err)
	}
	slog.InfoContext(ctx, "Repository: All refresh tokens revoked for user", "userID", userID.String())
	return nil
}

func (r *UserRepo) UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE auth.users SET last_sign_in_at = NOW(), updated_at = NOW() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Error updating last_sign_in_at for user", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not update last_sign_in_at: %w", err)
	}
	slog.InfoContext(ctx, "Repository: last_sign_in_at updated for user", "userID", userID.String())
	return nil
}

// min helper for logging token hash safely
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}