package repository

import (
	"context"
	"database/sql"
	"fmt"
	"regexp" // SQLMock için regex eşleştirmesi
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq" // pq.Error için
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMockDBAndRepo, sqlmock ve UserRepo'yu test için döndürür.
func newMockDBAndRepo(t *testing.T) (*sql.DB, sqlmock.Sqlmock, UserRepoInterface) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := NewUserRepo(db)
	return db, mock, repo
}

func TestUserRepo_CreateUser_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	email := "test.create.repo@example.com"
	passwordHash := "repo_hashedpassword"
	fullName := "Repo Test User"
	expectedUserID := uuid.New()

	mock.ExpectBegin()

	userInsertQuery := regexp.QuoteMeta(`INSERT INTO auth.users (email, password_hash, full_name, is_active, email_verified) VALUES ($1, $2, $3, TRUE, FALSE) RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at`)
	mock.ExpectQuery(userInsertQuery).
		WithArgs(email, passwordHash, sql.NullString{String: fullName, Valid: true}).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "password_hash", "full_name", "is_active", "email_verified", "created_at", "updated_at", "last_sign_in_at"}).
			AddRow(expectedUserID, email, passwordHash, sql.NullString{String: fullName, Valid: true}, true, false, time.Now(), time.Now(), sql.NullTime{}))

	userRoleInsertQuery := regexp.QuoteMeta(`INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`)
	mock.ExpectExec(userRoleInsertQuery).
		WithArgs(expectedUserID, PassengerRoleID).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	createdUser, err := repo.CreateUser(context.Background(), email, passwordHash, fullName)

	assert.NoError(t, err)
	require.NotNil(t, createdUser)
	assert.Equal(t, expectedUserID, createdUser.ID)
	assert.Equal(t, email, createdUser.Email)

	assert.NoError(t, mock.ExpectationsWereMet(), "SQL mock beklentileri karşılanmadı")
}

func TestUserRepo_CreateUser_EmailExists(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	email := "existing.repo@example.com"
	// pq.Error'ı doğru şekilde oluşturmak için gerekli alanları veriyoruz.
	// Gerçek bir pq.Error'ın tüm alanlarını doldurmak yerine, sadece Code alanını içeren
	// ve Error() metodunda "duplicate key" gibi bir ifade döndüren bir custom error da mocklanabilir.
	// Şimdilik, fmt.Errorf ile repository katmanının döndüğü hatayı taklit ediyoruz.
	// Repository katmanımız zaten pq.Error'ı kontrol edip kendi hata mesajını üretiyor.
	mockErr := &pq.Error{Code: "23505"} // Sadece Code alanı yeterli olabilir mock için

	mock.ExpectBegin()
	userInsertQuery := regexp.QuoteMeta(`INSERT INTO auth.users (email, password_hash, full_name, is_active, email_verified) VALUES ($1, $2, $3, TRUE, FALSE) RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at`)
	mock.ExpectQuery(userInsertQuery).
		WithArgs(email, "anyhash", sql.NullString{String: "anyname", Valid: true}).
		WillReturnError(mockErr) // pq.Error döndür

	mock.ExpectRollback()

	_, err := repo.CreateUser(context.Background(), email, "anyhash", "anyname")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email 'existing.repo@example.com' already exists")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetUserByEmail_NotFound(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t) // Bu helper fonksiyonumuz zaten var
	defer db.Close()

	email := "nonexistent@example.com"

	userSelectQuery := regexp.QuoteMeta(
		`SELECT id, password_hash, full_name, is_active, email_verified FROM auth.users WHERE email = $1`,
	)
	mock.ExpectQuery(userSelectQuery).
		WithArgs(email).
		WillReturnError(sql.ErrNoRows) // sql.ErrNoRows döndüğünü mock'luyoruz

	userInfo, pwHash, isActive, err := repo.GetUserByEmail(context.Background(), email)

	assert.Nil(t, userInfo, "userInfo nil olmalı çünkü kullanıcı bulunamadı")
	assert.Empty(t, pwHash, "passwordHash boş olmalı çünkü kullanıcı bulunamadı")
	assert.False(t, isActive, "isActive false olmalı çünkü kullanıcı bulunamadı")
	require.Error(t, err, "Hata dönmeliydi")
	assert.Contains(t, err.Error(), fmt.Sprintf("user with email '%s' not found", email), "Hata mesajı beklenen gibi olmalı")

	assert.NoError(t, mock.ExpectationsWereMet(), "SQL mock beklentileri karşılanmadı")
}

func TestUserRepo_GetUserByID_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	expectedEmail := "byid.repo@example.com"
	expectedFullName := "By ID User Repo"
	expectedIsActive := true
	expectedEmailVerified := false // Test için farklı bir değer

	// auth.users sorgusu için beklenti
	idSelectQuery := regexp.QuoteMeta(
		`SELECT email, full_name, is_active, email_verified FROM auth.users WHERE id = $1`,
	)
	mock.ExpectQuery(idSelectQuery).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows(
			[]string{"email", "full_name", "is_active", "email_verified"},
		).AddRow(
			expectedEmail, sql.NullString{String: expectedFullName, Valid: true}, expectedIsActive, expectedEmailVerified,
		))

	// auth.roles sorgusu için beklenti
	rolesQuery := regexp.QuoteMeta(
		`SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`,
	)
	mock.ExpectQuery(rolesQuery).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("passenger"))

	userInfo, err := repo.GetUserByID(context.Background(), userID)

	require.NoError(t, err)
	require.NotNil(t, userInfo)
	assert.Equal(t, userID.String(), userInfo.UserId)
	assert.Equal(t, expectedEmail, userInfo.Email)
	assert.Equal(t, expectedFullName, userInfo.FullName)
	assert.True(t, userInfo.IsActive) // Bu, mock'ladığımız değere göre olmalı
	assert.False(t, userInfo.EmailVerified)
	assert.Contains(t, userInfo.Roles, "passenger")

	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetUserByID_NotFound(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()

	idSelectQuery := regexp.QuoteMeta(
		`SELECT email, full_name, is_active, email_verified FROM auth.users WHERE id = $1`,
	)
	mock.ExpectQuery(idSelectQuery).
		WithArgs(userID).
		WillReturnError(sql.ErrNoRows)

	userInfo, err := repo.GetUserByID(context.Background(), userID)

	assert.Nil(t, userInfo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("user with ID '%s' not found", userID.String()))

	assert.NoError(t, mock.ExpectationsWereMet())
}
func TestUserRepo_StoreRefreshToken_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	tokenHash := "test_token_hash"
	expiresAt := time.Now().Add(time.Hour * 24 * 7)

	query := regexp.QuoteMeta(`INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`)
	mock.ExpectExec(query).
		WithArgs(userID, tokenHash, expiresAt).
		WillReturnResult(sqlmock.NewResult(1, 1)) // Bir satır eklendi, bir satır etkilendi

	err := repo.StoreRefreshToken(context.Background(), userID, tokenHash, expiresAt)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet(), "SQL mock beklentileri karşılanmadı")
}

func TestUserRepo_StoreRefreshToken_DuplicateKey(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	tokenHash := "duplicate_token_hash"
	expiresAt := time.Now().Add(time.Hour)
	pqErr := &pq.Error{Code: "23505"} // Unique constraint violation

	query := regexp.QuoteMeta(`INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`)
	mock.ExpectExec(query).
		WithArgs(userID, tokenHash, expiresAt).
		WillReturnError(pqErr)

	err := repo.StoreRefreshToken(context.Background(), userID, tokenHash, expiresAt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token hash already exists")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- GetRefreshTokenByHash ---
func TestUserRepo_GetRefreshTokenByHash_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	expectedID := uuid.New()
	expectedUserID := uuid.New()
	tokenHash := "valid_token_hash"
	now := time.Now()
	expectedExpiresAt := now.Add(time.Hour)

	rows := sqlmock.NewRows([]string{"id", "user_id", "token_hash", "expires_at", "revoked", "created_at"}).
		AddRow(expectedID, expectedUserID, tokenHash, expectedExpiresAt, false, now)

	query := regexp.QuoteMeta(
		`SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM auth.refresh_tokens WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`)
	mock.ExpectQuery(query).
		WithArgs(tokenHash).
		WillReturnRows(rows)

	rt, err := repo.GetRefreshTokenByHash(context.Background(), tokenHash)
	require.NoError(t, err)
	require.NotNil(t, rt)
	assert.Equal(t, expectedID, rt.ID)
	assert.Equal(t, expectedUserID, rt.UserID)
	assert.Equal(t, tokenHash, rt.TokenHash)
	assert.WithinDuration(t, expectedExpiresAt, rt.ExpiresAt, time.Second) // Zaman karşılaştırması için
	assert.False(t, rt.Revoked)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetRefreshTokenByHash_NotFoundOrRevokedOrExpired(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	tokenHash := "not_found_token_hash"
	query := regexp.QuoteMeta(
		`SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM auth.refresh_tokens WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`)
	mock.ExpectQuery(query).
		WithArgs(tokenHash).
		WillReturnError(sql.ErrNoRows)

	rt, err := repo.GetRefreshTokenByHash(context.Background(), tokenHash)
	assert.Nil(t, rt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token not found, expired, or revoked")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- RevokeRefreshTokenByHash ---
func TestUserRepo_RevokeRefreshTokenByHash_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	tokenHash := "token_to_revoke"
	query := regexp.QuoteMeta(
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND revoked = FALSE`)
	mock.ExpectExec(query).
		WithArgs(tokenHash).
		WillReturnResult(sqlmock.NewResult(0, 1)) // Bir satır etkilendi

	err := repo.RevokeRefreshTokenByHash(context.Background(), tokenHash)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_RevokeRefreshTokenByHash_NoneToRevoke(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	tokenHash := "already_revoked_or_not_found_token"
	query := regexp.QuoteMeta(
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND revoked = FALSE`)
	mock.ExpectExec(query).
		WithArgs(tokenHash).
		WillReturnResult(sqlmock.NewResult(0, 0)) // Hiçbir satır etkilenmedi

	err := repo.RevokeRefreshTokenByHash(context.Background(), tokenHash)
	assert.NoError(t, err) // Fonksiyon hata dönmüyor, sadece logluyor
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- RevokeAllRefreshTokensForUser ---
func TestUserRepo_RevokeAllRefreshTokensForUser_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	query := regexp.QuoteMeta(
		`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`)
	mock.ExpectExec(query).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 3)) // Örnek olarak 3 token revoke edildi

	err := repo.RevokeAllRefreshTokensForUser(context.Background(), userID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- UpdateUserLastSignInAt ---
func TestUserRepo_UpdateUserLastSignInAt_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	query := regexp.QuoteMeta(
		`UPDATE auth.users SET last_sign_in_at = NOW(), updated_at = NOW() WHERE id = $1`)
	mock.ExpectExec(query).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1)) // Bir satır etkilendi

	err := repo.UpdateUserLastSignInAt(context.Background(), userID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}