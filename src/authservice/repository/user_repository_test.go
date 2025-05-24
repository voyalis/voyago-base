package repository

import (
	"context"
	"database/sql"
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

// TODO: GetUserByEmail, GetUserByID, StoreRefreshToken, GetRefreshTokenByHash,
// RevokeRefreshTokenByHash, RevokeAllRefreshTokensForUser, UpdateUserLastSignInAt
// için başarılı ve hata durumlarını içeren kapsamlı unit testler yazılacak.