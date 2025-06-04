// src/core/identity/authservice/repository/user_repo.go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	pb "github.com/voyalis/voyago-base/gen/go/core/identity/v1"
)

// min helper: iki int değerinden küçüğünü döner (örn: token hash prefix string göstermek için)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const (
	PassengerRoleID = 1
)

// User modeli
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

// RefreshToken modeli
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ParentID  uuid.NullUUID
	Revoked   bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

// PasswordResetToken modeli
type PasswordResetToken struct {
	TokenHash string
	UserID    uuid.UUID
	ExpiresAt time.Time
	CreatedAt time.Time
	Consumed  bool
}

// EmailVerificationToken modeli
type EmailVerificationToken struct {
	TokenHash string
	UserID    uuid.UUID
	Email     string
	ExpiresAt time.Time
	CreatedAt time.Time
	Consumed  bool
}

// UserRepoInterface: servisin ihtiyaç duyduğu repository metotlarını tanımlar
type UserRepoInterface interface {
	CreateUser(ctx context.Context, email, passwordHash, fullName string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error)
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
	StoreEmailVerificationToken(ctx context.Context, userID uuid.UUID, email string, tokenHash string, expiresAt time.Time) error
	GetValidEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*EmailVerificationToken, error)
	MarkEmailVerificationTokenAsUsed(ctx context.Context, tokenHash string) error
	MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error
	UpdateUserFullName(ctx context.Context, userID uuid.UUID, newFullName string) error
}

// UserRepo, gerçek database bağlantısını tutar
type UserRepo struct {
	db *sql.DB
}

// NewUserRepo, UserRepoInterface’i implemente eden bir örneği döner
func NewUserRepo(database *sql.DB) UserRepoInterface {
	return &UserRepo{db: database}
}

// Aşağıda sırasıyla tüm metotlar eklidir:

// CreateUser: Yeni kullanıcı oluşturur
func (r *UserRepo) CreateUser(ctx context.Context, email, passwordHash, fullName string) (*User, error) {
	targetDB := r.db
	var newUser User
	var err error

	tx, errTx := targetDB.BeginTx(ctx, nil)
	if errTx != nil {
		slog.ErrorContext(ctx, "Repository: Tx başlatılamadı", "error", errTx)
		return nil, fmt.Errorf("could not start transaction: %w", errTx)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			slog.ErrorContext(ctx, "Repository: Transaction panic yakalandı", "panic", p)
			panic(p)
		} else if err != nil {
			slog.WarnContext(ctx, "Repository: Transaction geri alınıyor", "error", err)
			_ = tx.Rollback()
		} else {
			err = tx.Commit()
			if err != nil {
				slog.ErrorContext(ctx, "Repository: Transaction commit hatası", "error", err)
			}
		}
	}()

	userQuery := `
		INSERT INTO auth.users
			(email, password_hash, full_name, is_active, email_verified)
		VALUES ($1, $2, $3, TRUE, FALSE)
		RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at
	`
	var sqlFullName sql.NullString
	if fullName != "" {
		sqlFullName = sql.NullString{String: fullName, Valid: true}
	}

	err = tx.QueryRowContext(ctx, userQuery, email, passwordHash, sqlFullName).Scan(
		&newUser.ID,
		&newUser.Email,
		&newUser.PasswordHash,
		&newUser.FullName,
		&newUser.IsActive,
		&newUser.EmailVerified,
		&newUser.CreatedAt,
		&newUser.UpdatedAt,
		&newUser.LastSignInAt,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			err = fmt.Errorf("email '%s' zaten kayıtlı", email)
			slog.WarnContext(ctx, "Repository: Kullanıcı e-posta çakışması", "email", email, "pg_code", pgErr.Code)
			return nil, err
		}
		slog.ErrorContext(ctx, "Repository: Kullanıcı ekleme hatası", "email", email, "error", err)
		err = fmt.Errorf("could not create user: %w", err)
		return nil, err
	}

	roleQuery := `
		INSERT INTO auth.user_roles (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`
	_, err = tx.ExecContext(ctx, roleQuery, newUser.ID, PassengerRoleID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Default rol atama hatası", "userID", newUser.ID.String(), "error", err)
		err = fmt.Errorf("could not assign default role: %w", err)
		return nil, err
	}

	slog.InfoContext(ctx, "Repository: Kullanıcı oluşturuldu", "userID", newUser.ID.String(), "email", newUser.Email)
	return &newUser, nil
}

// GetUserByEmail: Email’le kullanıcıyı ve hash’ini döner
func (r *UserRepo) GetUserByEmail(ctx context.Context, email string) (*pb.UserInfo, string, bool, error) {
	var userID uuid.UUID
	var storedPasswordHash string
	var userFullName sql.NullString
	var isActive, emailVerified bool

	userQuery := `
		SELECT id, password_hash, full_name, is_active, email_verified
		FROM auth.users
		WHERE email = $1
	`
	err := r.db.QueryRowContext(ctx, userQuery, email).Scan(
		&userID,
		&storedPasswordHash,
		&userFullName,
		&isActive,
		&emailVerified,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: Email ile kullanıcı bulunamadı", "email", email)
			return nil, "", false, fmt.Errorf("user with email '%s' not found", email)
		}
		slog.ErrorContext(ctx, "Repository: Email ile kullanıcı alma hatası", "email", email, "error", err)
		return nil, "", false, fmt.Errorf("database error: %w", err)
	}

	// Rolleri oku
	var roles []string
	rolesQuery := `
		SELECT r.name
		FROM auth.roles r
		JOIN auth.user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`
	rows, err := r.db.QueryContext(ctx, rolesQuery, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Rolleri alırken hata", "userID", userID.String(), "error", err)
		return nil, "", false, fmt.Errorf("db error fetching roles: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var roleName string
		if err = rows.Scan(&roleName); err != nil {
			slog.ErrorContext(ctx, "Repository: Rol tarama hatası", "userID", userID.String(), "error", err)
			return nil, "", false, fmt.Errorf("db error scanning role: %w", err)
		}
		roles = append(roles, roleName)
	}
	if err = rows.Err(); err != nil {
		slog.ErrorContext(ctx, "Repository: Roller iterasyon sonrası hata", "userID", userID.String(), "error", err)
		return nil, "", false, fmt.Errorf("db error iterating roles: %w", err)
	}
	if len(roles) == 0 {
		slog.WarnContext(ctx, "Repository: Kullanıcıya rol atanmadı, varsayılan 'passenger' eklendi", "userID", userID.String())
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
	slog.DebugContext(ctx, "Repository: Kullanıcı email ile alındı", "userID", userID.String(), "isActive", isActive)

	return userInfo, storedPasswordHash, isActive, nil
}

// GetUserByID: ID ile kullanıcıyı döner
func (r *UserRepo) GetUserByID(ctx context.Context, userID uuid.UUID) (*pb.UserInfo, error) {
	var userEmail string
	var userFullName sql.NullString
	var isActive, emailVerified bool

	userQuery := `
		SELECT email, full_name, is_active, email_verified
		FROM auth.users
		WHERE id = $1
	`
	err := r.db.QueryRowContext(ctx, userQuery, userID).Scan(
		&userEmail,
		&userFullName,
		&isActive,
		&emailVerified,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: ID ile kullanıcı bulunamadı", "userID", userID.String())
			return nil, fmt.Errorf("user with ID '%s' not found", userID.String())
		}
		slog.ErrorContext(ctx, "Repository: ID ile kullanıcı alma hatası", "userID", userID.String(), "error", err)
		return nil, fmt.Errorf("db error fetching user by ID: %w", err)
	}

	// Rolleri oku
	var roles []string
	rolesQuery := `
		SELECT r.name
		FROM auth.roles r
		JOIN auth.user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
	`
	rows, err := r.db.QueryContext(ctx, rolesQuery, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Rolleri (ID ile) alırken hata", "userID", userID.String(), "error", err)
		return nil, fmt.Errorf("db error fetching roles by ID: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var roleName string
		if err = rows.Scan(&roleName); err != nil {
			slog.ErrorContext(ctx, "Repository: Rol tarama hatası (ID ile)", "userID", userID.String(), "error", err)
			return nil, fmt.Errorf("db error scanning role by ID: %w", err)
		}
		roles = append(roles, roleName)
	}
	if err = rows.Err(); err != nil {
		slog.ErrorContext(ctx, "Repository: Roller iterasyon sonrası hata (ID ile)", "userID", userID.String(), "error", err)
		return nil, fmt.Errorf("db error iterating roles by ID: %w", err)
	}
	if len(roles) == 0 {
		slog.WarnContext(ctx, "Repository: Kullanıcıya rol atanmadı (ID ile), varsayılan 'passenger' eklendi", "userID", userID.String())
		roles = append(roles, "passenger")
	}

	userInfo := &pb.UserInfo{
		UserId:        userID.String(),
		Email:         userEmail,
		FullName:      userFullName.String,
		Roles:         roles,
		IsActive:      isActive,
		EmailVerified: emailVerified,
	}
	slog.DebugContext(ctx, "Repository: Kullanıcı ID ile alındı", "userID", userID.String())

	return userInfo, nil
}

// StoreRefreshToken: Yeni bir refresh token kaydeder
func (r *UserRepo) StoreRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`
	_, err := r.db.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			slog.WarnContext(ctx, "Repository: Refresh token çakışması", "userID", userID.String())
			return fmt.Errorf("refresh token hash already exists")
		}
		slog.ErrorContext(ctx, "Repository: Refresh token kaydetme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not store refresh token: %w", err)
	}
	slog.InfoContext(ctx, "Repository: Refresh token kaydedildi", "userID", userID.String())
	return nil
}

// GetRefreshTokenByHash: Aktif (revoke edilmemiş, süresi dolmamış) token'ı döner
func (r *UserRepo) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var rt RefreshToken
	query := `
		SELECT id, user_id, token_hash, expires_at, revoked, created_at
		FROM auth.refresh_tokens
		WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()
	`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&rt.ID,
		&rt.UserID,
		&rt.TokenHash,
		&rt.ExpiresAt,
		&rt.Revoked,
		&rt.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: Refresh token bulunamadı veya geçersiz", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
			return nil, fmt.Errorf("refresh token not found, expired, or revoked")
		}
		slog.ErrorContext(ctx, "Repository: Refresh token alma hatası", "error", err)
		return nil, fmt.Errorf("could not get refresh token: %w", err)
	}
	slog.DebugContext(ctx, "Repository: Refresh token alındı", "userID", rt.UserID.String())
	return &rt, nil
}

// RevokeRefreshTokenByHash: Belirli bir refresh token’ı iptal eder
func (r *UserRepo) RevokeRefreshTokenByHash(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE auth.refresh_tokens
		SET revoked = TRUE
		WHERE token_hash = $1 AND revoked = FALSE
	`
	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Refresh token iptal hatası", "error", err)
		return fmt.Errorf("could not revoke refresh token: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: Revoked edilecek aktif refresh token bulunamadı")
	} else {
		slog.InfoContext(ctx, "Repository: Refresh token başarıyla iptal edildi")
	}
	return nil
}

// RevokeAllRefreshTokensForUser: Kullanıcının tüm aktif tokenlarını iptal eder
func (r *UserRepo) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth.refresh_tokens
		SET revoked = TRUE
		WHERE user_id = $1 AND revoked = FALSE
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Tüm refresh tokenlarını iptal etme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not revoke all refresh tokens: %w", err)
	}
	slog.InfoContext(ctx, "Repository: Tüm aktif refresh tokenlar iptal edildi", "userID", userID.String())
	return nil
}

// UpdateUserLastSignInAt: kullanıcı son giriş zamanını günceller
func (r *UserRepo) UpdateUserLastSignInAt(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth.users
		SET last_sign_in_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: last_sign_in_at güncelleme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not update last_sign_in_at: %w", err)
	}
	slog.InfoContext(ctx, "Repository: last_sign_in_at güncellendi", "userID", userID.String())
	return nil
}

// StorePasswordResetToken: Şifre sıfırlama token’ını saklar (varsa update eder)
func (r *UserRepo) StorePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at, consumed)
		VALUES ($1, $2, $3, FALSE)
		ON CONFLICT (token_hash) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			expires_at = EXCLUDED.expires_at,
			consumed = FALSE,
			created_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Şifre sıfırlama token kaydetme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not store password reset token: %w", err)
	}
	slog.InfoContext(ctx, "Repository: Şifre sıfırlama token kaydedildi", "userID", userID.String(), "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	return nil
}

// GetValidPasswordResetTokenByHash: Geçerli (non-consumed, süresi dolmamış) token’ı döner
func (r *UserRepo) GetValidPasswordResetTokenByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	var prt PasswordResetToken
	query := `
		SELECT token_hash, user_id, expires_at, created_at, consumed
		FROM auth.password_reset_tokens
		WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()
	`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&prt.TokenHash,
		&prt.UserID,
		&prt.ExpiresAt,
		&prt.CreatedAt,
		&prt.Consumed,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: Şifre sıfırlama token bulunamadı veya süresi dolmuş/consumed", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
			return nil, fmt.Errorf("password reset token not found, expired, or consumed")
		}
		slog.ErrorContext(ctx, "Repository: Şifre sıfırlama token alma hatası", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return nil, fmt.Errorf("could not get password reset token: %w", err)
	}
	slog.DebugContext(ctx, "Repository: Şifre sıfırlama token bulundu", "userID", prt.UserID.String())
	return &prt, nil
}

// MarkPasswordResetTokenAsUsed: Token’ı consumed = true yapar
func (r *UserRepo) MarkPasswordResetTokenAsUsed(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE auth.password_reset_tokens
		SET consumed = TRUE
		WHERE token_hash = $1 AND consumed = FALSE
	`
	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Şifre sıfırlama token consumed hatası", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return fmt.Errorf("could not mark password reset token as used: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: İşaretlenecek aktif şifre sıfırlama token bulunamadı", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	} else {
		slog.InfoContext(ctx, "Repository: Şifre sıfırlama token consumed edildi", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	}
	return nil
}

// UpdateUserPassword: Kullanıcının şifresini günceller
func (r *UserRepo) UpdateUserPassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	query := `
		UPDATE auth.users
		SET password_hash = $1, updated_at = NOW()
		WHERE id = $2
	`
	result, err := r.db.ExecContext(ctx, query, newPasswordHash, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Kullanıcı şifre güncelleme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not update user password: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: Şifre güncellenmedi - kullanıcı bulunamadı veya aynı hash", "userID", userID.String())
		return fmt.Errorf("user not found to update password, or no change needed")
	}
	slog.InfoContext(ctx, "Repository: Kullanıcı şifresi güncellendi", "userID", userID.String())
	return nil
}

// ─── E-posta Doğrulama Tokenları ──────────────────────────────────────────

// StoreEmailVerificationToken: Yeni veya güncellenmiş bir e-posta doğrulama token’ı kaydeder
func (r *UserRepo) StoreEmailVerificationToken(ctx context.Context, userID uuid.UUID, email string, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO auth.email_verification_tokens (user_id, email, token_hash, expires_at, consumed)
		VALUES ($1, $2, $3, $4, FALSE)
		ON CONFLICT (token_hash) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			email = EXCLUDED.email,
			expires_at = EXCLUDED.expires_at,
			consumed = FALSE,
			created_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query, userID, email, tokenHash, expiresAt)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: E-posta doğrulama token kaydetme hatası", "userID", userID.String(), "email", email, "error", err)
		return fmt.Errorf("could not store email verification token: %w", err)
	}
	slog.InfoContext(ctx, "Repository: E-posta doğrulama token saklandı", "userID", userID.String(), "email", email, "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	return nil
}

// GetValidEmailVerificationTokenByHash: Geçerli (non-consumed, süresi dolmamış) e-posta doğrulama token’ı döner
func (r *UserRepo) GetValidEmailVerificationTokenByHash(ctx context.Context, tokenHash string) (*EmailVerificationToken, error) {
	var evt EmailVerificationToken
	query := `
		SELECT token_hash, user_id, email, expires_at, created_at, consumed
		FROM auth.email_verification_tokens
		WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()
	`
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&evt.TokenHash,
		&evt.UserID,
		&evt.Email,
		&evt.ExpiresAt,
		&evt.CreatedAt,
		&evt.Consumed,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			slog.DebugContext(ctx, "Repository: E-posta doğrulama token bulunamadı veya süresi dolmuş/consumed", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
			return nil, fmt.Errorf("email verification token not found, expired, or consumed")
		}
		slog.ErrorContext(ctx, "Repository: E-posta doğrulama token alma hatası", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return nil, fmt.Errorf("could not get email verification token: %w", err)
	}
	slog.DebugContext(ctx, "Repository: E-posta doğrulama token bulundu", "userID", evt.UserID.String(), "email", evt.Email)
	return &evt, nil
}

// MarkEmailVerificationTokenAsUsed: Token’ı consumed = true yapar
func (r *UserRepo) MarkEmailVerificationTokenAsUsed(ctx context.Context, tokenHash string) error {
	query := `
		UPDATE auth.email_verification_tokens
		SET consumed = TRUE
		WHERE token_hash = $1 AND consumed = FALSE
	`
	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: E-posta doğrulama token consumed hatası", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))], "error", err)
		return fmt.Errorf("could not mark email verification token as used: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: İşaretlenecek aktif e-posta doğrulama token bulunamadı", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	} else {
		slog.InfoContext(ctx, "Repository: E-posta doğrulama token consumed edildi", "tokenHash_prefix", tokenHash[:min(8, len(tokenHash))])
	}
	return nil
}

// MarkUserEmailAsVerified: Kullanıcının email_verified alanını true yapar
func (r *UserRepo) MarkUserEmailAsVerified(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE auth.users
		SET email_verified = TRUE, updated_at = NOW()
		WHERE id = $1 AND email_verified = FALSE
	`
	result, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: Kullanıcı email_verified güncelleme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not mark user email as verified: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		slog.InfoContext(ctx, "Repository: Kullanıcı email zaten doğrulanmış veya bulunamadı", "userID", userID.String())
	} else {
		slog.InfoContext(ctx, "Repository: Kullanıcı email verified olarak işaretlendi", "userID", userID.String())
	}
	return nil
}

// UpdateUserFullName: Kullanıcının full_name alanını günceller (boş string gelirse NULL atar)
func (r *UserRepo) UpdateUserFullName(ctx context.Context, userID uuid.UUID, newFullName string) error {
	query := `
		UPDATE auth.users
		SET full_name = $1, updated_at = NOW()
		WHERE id = $2
	`

	var sqlFullName sql.NullString
	if newFullName != "" {
		sqlFullName = sql.NullString{String: newFullName, Valid: true}
	} else {
		sqlFullName = sql.NullString{Valid: false}
	}

	result, err := r.db.ExecContext(ctx, query, sqlFullName, userID)
	if err != nil {
		slog.ErrorContext(ctx, "Repository: full_name güncelleme hatası", "userID", userID.String(), "error", err)
		return fmt.Errorf("could not update user full_name: %w", err)
	}

	rowsAffected, errRows := result.RowsAffected()
	if errRows != nil {
		slog.WarnContext(ctx, "Repository: RowsAffected sonucu alınamadı", "userID", userID.String(), "error", errRows)
	} else if rowsAffected == 0 {
		slog.WarnContext(ctx, "Repository: full_name güncellenecek kullanıcı bulunamadı veya aynı full_name", "userID", userID.String(), "newFullName", newFullName)
	}

	slog.InfoContext(ctx, "Repository: Kullanıcı full_name güncellendi", "userID", userID.String(), "newFullName", newFullName)
	return nil
}
