package repository

// user_repository_tet.go

import (
	"context"
	"database/sql"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockDBAndRepo(t *testing.T) (*sql.DB, sqlmock.Sqlmock, UserRepoInterface) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	repo := NewUserRepo(db)
	return db, mock, repo
}

func TestUserRepo_CreateUser_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()
	email := "test.create.repo@example.com"; passwordHash := "repo_hashedpassword"; fullName := "Repo Test User"; expectedUserID := uuid.New()
	mock.ExpectBegin()
	userInsertQuery := regexp.QuoteMeta(`INSERT INTO auth.users (email, password_hash, full_name, is_active, email_verified) VALUES ($1, $2, $3, TRUE, FALSE) RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at`)
	mock.ExpectQuery(userInsertQuery).WithArgs(email, passwordHash, sql.NullString{String: fullName, Valid: true}).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "password_hash", "full_name", "is_active", "email_verified", "created_at", "updated_at", "last_sign_in_at"}).
			AddRow(expectedUserID, email, passwordHash, sql.NullString{String: fullName, Valid: true}, true, false, time.Now(), time.Now(), sql.NullTime{}))
	userRoleInsertQuery := regexp.QuoteMeta(`INSERT INTO auth.user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING`)
	mock.ExpectExec(userRoleInsertQuery).WithArgs(expectedUserID, PassengerRoleID).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	createdUser, err := repo.CreateUser(context.Background(), email, passwordHash, fullName)
	assert.NoError(t, err); require.NotNil(t, createdUser); assert.Equal(t, expectedUserID, createdUser.ID); assert.Equal(t, email, createdUser.Email)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_CreateUser_EmailExists(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()
	email := "existing.repo@example.com"; mockErr := &pq.Error{Code: "23505"}
	mock.ExpectBegin()
	userInsertQuery := regexp.QuoteMeta(`INSERT INTO auth.users (email, password_hash, full_name, is_active, email_verified) VALUES ($1, $2, $3, TRUE, FALSE) RETURNING id, email, password_hash, full_name, is_active, email_verified, created_at, updated_at, last_sign_in_at`)
	mock.ExpectQuery(userInsertQuery).WithArgs(email, "anyhash", sql.NullString{String: "anyname", Valid: true}).WillReturnError(mockErr)
	mock.ExpectRollback()
	_, err := repo.CreateUser(context.Background(), email, "anyhash", "anyname")
	assert.Error(t, err); assert.Contains(t, err.Error(), "email 'existing.repo@example.com' already exists")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetUserByEmail_NotFound(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()
	email := "nonexistent.repo@example.com"
	userSelectQuery := regexp.QuoteMeta(`SELECT id, password_hash, full_name, is_active, email_verified FROM auth.users WHERE email = $1`)
	mock.ExpectQuery(userSelectQuery).WithArgs(email).WillReturnError(sql.ErrNoRows)
	userInfo, pwHash, isActive, err := repo.GetUserByEmail(context.Background(), email)
	assert.Nil(t, userInfo); assert.Empty(t, pwHash); assert.False(t, isActive); require.Error(t, err); assert.Contains(t, err.Error(), "not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetUserByEmail_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t); defer db.Close(); email := "getuser.repo.success@example.com"
	expectedID := uuid.New(); expectedHash := "storedHashSuccess"; expectedName := "Get User Success"; expectedIsActive := true; expectedEmailVerified := true
	userRows := sqlmock.NewRows([]string{"id", "password_hash", "full_name", "is_active", "email_verified"}).AddRow(expectedID, expectedHash, sql.NullString{String: expectedName, Valid: true}, expectedIsActive, expectedEmailVerified)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, password_hash, full_name, is_active, email_verified FROM auth.users WHERE email = $1`)).WithArgs(email).WillReturnRows(userRows)
	roleRows := sqlmock.NewRows([]string{"name"}).AddRow("passenger").AddRow("admin")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`)).WithArgs(expectedID).WillReturnRows(roleRows)
	userInfo, pwHash, isActive, err := repo.GetUserByEmail(context.Background(), email)
	require.NoError(t, err); require.NotNil(t, userInfo); assert.Equal(t, expectedID.String(), userInfo.UserId); assert.Equal(t, email, userInfo.Email)
	assert.Equal(t, expectedName, userInfo.FullName); assert.ElementsMatch(t, []string{"passenger", "admin"}, userInfo.Roles); assert.True(t, isActive); assert.Equal(t, expectedHash, pwHash)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetUserByID_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t); defer db.Close(); userID := uuid.New()
	expectedEmail := "byid.repo.success@example.com"; expectedName := "By ID Success"; expectedIsActive := true; expectedEmailVerified := true
	idSelectQuery := regexp.QuoteMeta(`SELECT email, full_name, is_active, email_verified FROM auth.users WHERE id = $1`)
	mock.ExpectQuery(idSelectQuery).WithArgs(userID).WillReturnRows(sqlmock.NewRows([]string{"email", "full_name", "is_active", "email_verified"}).AddRow(expectedEmail, sql.NullString{String: expectedName, Valid: true}, expectedIsActive, expectedEmailVerified))
	rolesQuery := regexp.QuoteMeta(`SELECT r.name FROM auth.roles r JOIN auth.user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1`)
	mock.ExpectQuery(rolesQuery).WithArgs(userID).WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("admin"))
	userInfo, err := repo.GetUserByID(context.Background(), userID)
	require.NoError(t, err); require.NotNil(t, userInfo); assert.Equal(t, userID.String(), userInfo.UserId); assert.Equal(t, expectedEmail, userInfo.Email)
	assert.Equal(t, expectedName, userInfo.FullName); assert.True(t, userInfo.IsActive); assert.True(t, userInfo.EmailVerified); assert.Contains(t, userInfo.Roles, "admin")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetUserByID_NotFound(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t); defer db.Close(); userID := uuid.New()
	idSelectQuery := regexp.QuoteMeta(`SELECT email, full_name, is_active, email_verified FROM auth.users WHERE id = $1`)
	mock.ExpectQuery(idSelectQuery).WithArgs(userID).WillReturnError(sql.ErrNoRows)
	userInfo, err := repo.GetUserByID(context.Background(), userID)
	assert.Nil(t, userInfo); require.Error(t, err); assert.Contains(t, err.Error(), "not found")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Refresh Token Metotları İçin Testler ---
func TestUserRepo_StoreRefreshToken_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    userID := uuid.New(); tokenHash := "new_refresh_hash"; expiresAt := time.Now().Add(time.Hour)
    query := regexp.QuoteMeta(`INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`)
    mock.ExpectExec(query).WithArgs(userID, tokenHash, expiresAt).WillReturnResult(sqlmock.NewResult(1, 1))
    err := repo.StoreRefreshToken(context.Background(), userID, tokenHash, expiresAt)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_StoreRefreshToken_DuplicateHash(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    userID := uuid.New(); tokenHash := "duplicate_hash"; expiresAt := time.Now().Add(time.Hour)
    pqErr := &pq.Error{Code: "23505"} // Unique constraint violation on token_hash
    query := regexp.QuoteMeta(`INSERT INTO auth.refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`)
    mock.ExpectExec(query).WithArgs(userID, tokenHash, expiresAt).WillReturnError(pqErr)
    err := repo.StoreRefreshToken(context.Background(), userID, tokenHash, expiresAt)
    require.Error(t, err); assert.Contains(t, err.Error(), "refresh token hash already exists")
    assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetRefreshTokenByHash_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    expectedRtID := uuid.New(); expectedUserID := uuid.New(); tokenHash := "get_this_hash"; now := time.Now(); expiresAt := now.Add(time.Hour)
    rows := sqlmock.NewRows([]string{"id", "user_id", "token_hash", "expires_at", "revoked", "created_at"}).
        AddRow(expectedRtID, expectedUserID, tokenHash, expiresAt, false, now)
    query := regexp.QuoteMeta(`SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM auth.refresh_tokens WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`)
    mock.ExpectQuery(query).WithArgs(tokenHash).WillReturnRows(rows)
    rt, err := repo.GetRefreshTokenByHash(context.Background(), tokenHash)
    require.NoError(t, err); require.NotNil(t, rt); assert.Equal(t, expectedRtID, rt.ID); assert.Equal(t, expectedUserID, rt.UserID); assert.Equal(t, tokenHash, rt.TokenHash)
    assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetRefreshTokenByHash_NotFound(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    tokenHash := "non_existent_hash"
    query := regexp.QuoteMeta(`SELECT id, user_id, token_hash, expires_at, revoked, created_at FROM auth.refresh_tokens WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()`)
    mock.ExpectQuery(query).WithArgs(tokenHash).WillReturnError(sql.ErrNoRows)
    rt, err := repo.GetRefreshTokenByHash(context.Background(), tokenHash)
    assert.Nil(t, rt); require.Error(t, err); assert.Contains(t, err.Error(), "not found, expired, or revoked")
    assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_RevokeRefreshTokenByHash_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    tokenHash := "revoke_this_hash"
    query := regexp.QuoteMeta(`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE token_hash = $1 AND revoked = FALSE`)
    mock.ExpectExec(query).WithArgs(tokenHash).WillReturnResult(sqlmock.NewResult(0,1))
    err := repo.RevokeRefreshTokenByHash(context.Background(), tokenHash)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_RevokeAllRefreshTokensForUser_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    userID := uuid.New()
    query := regexp.QuoteMeta(`UPDATE auth.refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`)
    mock.ExpectExec(query).WithArgs(userID).WillReturnResult(sqlmock.NewResult(0,5)) // 5 tokens revoked
    err := repo.RevokeAllRefreshTokensForUser(context.Background(), userID)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_UpdateUserLastSignInAt_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    userID := uuid.New()
    query := regexp.QuoteMeta(`UPDATE auth.users SET last_sign_in_at = NOW(), updated_at = NOW() WHERE id = $1`)
    mock.ExpectExec(query).WithArgs(userID).WillReturnResult(sqlmock.NewResult(0,1))
    err := repo.UpdateUserLastSignInAt(context.Background(), userID)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}

// --- Password Reset Token Metotları İçin Testler ---
func TestUserRepo_StorePasswordResetToken_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    userID := uuid.New(); tokenHash := "reset_token_hash"; expiresAt := time.Now().Add(time.Minute * 15)
    query := regexp.QuoteMeta(`INSERT INTO auth.password_reset_tokens (user_id, token_hash, expires_at, consumed) VALUES ($1, $2, $3, FALSE) ON CONFLICT (token_hash) DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at, consumed = FALSE, created_at = NOW()`)
    mock.ExpectExec(query).WithArgs(userID, tokenHash, expiresAt).WillReturnResult(sqlmock.NewResult(1,1))
    err := repo.StorePasswordResetToken(context.Background(), userID, tokenHash, expiresAt)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetValidPasswordResetTokenByHash_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close()
    userID := uuid.New(); tokenHash := "valid_reset_hash"; now := time.Now(); expiresAt := now.Add(time.Minute * 10)
    rows := sqlmock.NewRows([]string{"token_hash", "user_id", "expires_at", "created_at", "consumed"}).
        AddRow(tokenHash, userID, expiresAt, now, false)
    query := regexp.QuoteMeta(`SELECT token_hash, user_id, expires_at, created_at, consumed FROM auth.password_reset_tokens WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()`)
    mock.ExpectQuery(query).WithArgs(tokenHash).WillReturnRows(rows)
    prt, err := repo.GetValidPasswordResetTokenByHash(context.Background(), tokenHash)
    require.NoError(t, err); require.NotNil(t, prt); assert.Equal(t, tokenHash, prt.TokenHash); assert.Equal(t, userID, prt.UserID)
    assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetValidPasswordResetTokenByHash_NotFound(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close(); tokenHash := "invalid_reset_hash"
    query := regexp.QuoteMeta(`SELECT token_hash, user_id, expires_at, created_at, consumed FROM auth.password_reset_tokens WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()`)
    mock.ExpectQuery(query).WithArgs(tokenHash).WillReturnError(sql.ErrNoRows)
    prt, err := repo.GetValidPasswordResetTokenByHash(context.Background(), tokenHash)
    assert.Nil(t, prt); require.Error(t, err); assert.Contains(t, err.Error(), "not found, expired, or consumed")
    assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_MarkPasswordResetTokenAsUsed_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close(); tokenHash := "consume_this_reset_hash"
    query := regexp.QuoteMeta(`UPDATE auth.password_reset_tokens SET consumed = TRUE WHERE token_hash = $1 AND consumed = FALSE`)
    mock.ExpectExec(query).WithArgs(tokenHash).WillReturnResult(sqlmock.NewResult(0,1))
    err := repo.MarkPasswordResetTokenAsUsed(context.Background(), tokenHash)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_UpdateUserPassword_Success(t *testing.T) {
    db, mock, repo := newMockDBAndRepo(t); defer db.Close(); userID := uuid.New(); newPasswordHash := "new_hashed_password"
    query := regexp.QuoteMeta(`UPDATE auth.users SET password_hash = $1, updated_at = NOW() WHERE id = $2`)
    mock.ExpectExec(query).WithArgs(newPasswordHash, userID).WillReturnResult(sqlmock.NewResult(0,1))
    err := repo.UpdateUserPassword(context.Background(), userID, newPasswordHash)
    assert.NoError(t, err); assert.NoError(t, mock.ExpectationsWereMet())
}
// --- Email Verification Token Metotları İçin Testler ---

func TestUserRepo_StoreEmailVerificationToken_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	email := "verify.email@example.com"
	tokenHash := "email_verify_hash_success"
	expiresAt := time.Now().Add(time.Hour * 24)

	query := regexp.QuoteMeta(`INSERT INTO auth.email_verification_tokens (user_id, email, token_hash, expires_at, consumed) VALUES ($1, $2, $3, $4, FALSE) ON CONFLICT (token_hash) DO UPDATE SET user_id = EXCLUDED.user_id, email = EXCLUDED.email, expires_at = EXCLUDED.expires_at, consumed = FALSE, created_at = NOW()`)
	mock.ExpectExec(query).
		WithArgs(userID, email, tokenHash, expiresAt).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.StoreEmailVerificationToken(context.Background(), userID, email, tokenHash, expiresAt)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetValidEmailVerificationTokenByHash_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	expectedTokenHash := "valid_email_verify_hash"
	expectedUserID := uuid.New()
	expectedEmail := "user.to.verify@example.com"
	now := time.Now()
	expectedExpiresAt := now.Add(time.Hour * 12)

	rows := sqlmock.NewRows([]string{"token_hash", "user_id", "email", "expires_at", "created_at", "consumed"}).
		AddRow(expectedTokenHash, expectedUserID, expectedEmail, expectedExpiresAt, now, false)

	query := regexp.QuoteMeta(`SELECT token_hash, user_id, email, expires_at, created_at, consumed FROM auth.email_verification_tokens WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()`)
	mock.ExpectQuery(query).
		WithArgs(expectedTokenHash).
		WillReturnRows(rows)

	evt, err := repo.GetValidEmailVerificationTokenByHash(context.Background(), expectedTokenHash)
	require.NoError(t, err)
	require.NotNil(t, evt)
	assert.Equal(t, expectedTokenHash, evt.TokenHash)
	assert.Equal(t, expectedUserID, evt.UserID)
	assert.Equal(t, expectedEmail, evt.Email)
	assert.WithinDuration(t, expectedExpiresAt, evt.ExpiresAt, time.Second)
	assert.False(t, evt.Consumed)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_GetValidEmailVerificationTokenByHash_NotFound(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	tokenHash := "nonexistent_email_verify_hash"
	query := regexp.QuoteMeta(`SELECT token_hash, user_id, email, expires_at, created_at, consumed FROM auth.email_verification_tokens WHERE token_hash = $1 AND consumed = FALSE AND expires_at > NOW()`)
	mock.ExpectQuery(query).
		WithArgs(tokenHash).
		WillReturnError(sql.ErrNoRows)

	evt, err := repo.GetValidEmailVerificationTokenByHash(context.Background(), tokenHash)
	assert.Nil(t, evt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email verification token not found, expired, or consumed")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_MarkEmailVerificationTokenAsUsed_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	tokenHash := "consume_this_email_verify_hash"
	query := regexp.QuoteMeta(`UPDATE auth.email_verification_tokens SET consumed = TRUE WHERE token_hash = $1 AND consumed = FALSE`)
	mock.ExpectExec(query).
		WithArgs(tokenHash).
		WillReturnResult(sqlmock.NewResult(0, 1)) // Bir satır etkilendi

	err := repo.MarkEmailVerificationTokenAsUsed(context.Background(), tokenHash)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_MarkUserEmailAsVerified_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	query := regexp.QuoteMeta(`UPDATE auth.users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1 AND email_verified = FALSE`)
	mock.ExpectExec(query).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1)) // Bir satır etkilendi

	err := repo.MarkUserEmailAsVerified(context.Background(), userID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_MarkUserEmailAsVerified_AlreadyVerified(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	query := regexp.QuoteMeta(`UPDATE auth.users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1 AND email_verified = FALSE`)
	mock.ExpectExec(query).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 0)) // Hiçbir satır etkilenmedi (zaten true'ydu)

	err := repo.MarkUserEmailAsVerified(context.Background(), userID)
	assert.NoError(t, err) // Hata dönmemeli, sadece loglamalı
	assert.NoError(t, mock.ExpectationsWereMet())
}

// --- UpdateUserFullName Metodu İçin Testler ---
func TestUserRepo_UpdateUserFullName_Success(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	newName := "Updated Test User Name"
	
	// sql.NullString ile eşleştirme
	expectedSQLFullName := sql.NullString{String: newName, Valid: true}

	query := regexp.QuoteMeta(`UPDATE auth.users SET full_name = $1, updated_at = NOW() WHERE id = $2`)
	mock.ExpectExec(query).
		WithArgs(expectedSQLFullName, userID). // Argümanı sql.NullString olarak bekliyoruz
		WillReturnResult(sqlmock.NewResult(0, 1)) // Bir satır etkilendi

	err := repo.UpdateUserFullName(context.Background(), userID, newName)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_UpdateUserFullName_EmptyNameSetsNull(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New()
	emptyName := ""
	
	// Boş string geldiğinde sql.NullString{Valid: false} beklenir
	expectedSQLNullFullName := sql.NullString{Valid: false} 

	query := regexp.QuoteMeta(`UPDATE auth.users SET full_name = $1, updated_at = NOW() WHERE id = $2`)
	mock.ExpectExec(query).
		WithArgs(expectedSQLNullFullName, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.UpdateUserFullName(context.Background(), userID, emptyName)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUserRepo_UpdateUserFullName_UserNotFound(t *testing.T) {
	db, mock, repo := newMockDBAndRepo(t)
	defer db.Close()

	userID := uuid.New() // Var olmayan bir kullanıcı ID'si
	newName := "NonExistent User Update"
	expectedSQLFullName := sql.NullString{String: newName, Valid: true}

	query := regexp.QuoteMeta(`UPDATE auth.users SET full_name = $1, updated_at = NOW() WHERE id = $2`)
	mock.ExpectExec(query).
		WithArgs(expectedSQLFullName, userID).
		WillReturnResult(sqlmock.NewResult(0, 0)) // Hiçbir satır etkilenmedi

	err := repo.UpdateUserFullName(context.Background(), userID, newName)
	assert.NoError(t, err) // Repository katmanı bu durumda hata dönmüyor, sadece logluyor
	assert.NoError(t, mock.ExpectationsWereMet())
}