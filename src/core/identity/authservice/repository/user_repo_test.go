// src/core/identity/authservice/repository/user_repo_test.go
package repository_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// “github.com/lib/pq” Postgres sürücüsünü kaydetmek için import ediyoruz
	_ "github.com/lib/pq"

	"github.com/voyalis/voyago-base/src/core/identity/authservice/repository"
)

var testDB *sql.DB

// TestMain, repodaki testler için tek seferlik DB bağlantısını hazırlar.
// Eğer ortam değişkenleri ayarlı değilse, testleri Skip edecek.
func TestMain(m *testing.M) {
	// ENV: TEST_DATABASE_URL="postgres://user:pass@localhost:5432/testdb?sslmode=disable"
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		// Eğer test veritabanı yoksa, doğrudan 0 döndür ve tüm testleri Skip et
		os.Exit(0)
	}

	var err error
	testDB, err = sql.Open("postgres", dsn)
	if err != nil {
		panic("Bağlantı açılamadı: " + err.Error())
	}
	// Kısa bir ping atarak DB’nin canlı olup olmadığını test edelim
	if errPing := testDB.Ping(); errPing != nil {
		panic("DB Ping başarısız: " + errPing.Error())
	}

	// db.InitDB yerine testDB’yi doğrudan UserRepo’ya geçiyoruz.
	// (Eğer db.InitDB sabit olarak kendi DB’yi açıyorsa, bu bağlantıyı atlamak için
	// test sırasında repository.NewUserRepo(testDB) kullanacağız.)
	code := m.Run()
	testDB.Close()
	os.Exit(code)
}

func TestCreateUser_And_GetByEmail(t *testing.T) {
	// Eğer TestMain içinde DB açılamadıysa (testDB == nil), atla.
	if testDB == nil {
		t.Skip("TEST_DATABASE_URL ayarlı değil; repository testleri atlanıyor.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := repository.NewUserRepo(testDB)

	// Rastgele kullanıcı oluşturmak için benzersiz bir e-posta
	email := "unittest_" + uuid.NewString()[:8] + "@example.com"
	passwordHash := "dummyhash"      // Gerçek testte bcrypt kullanabilirsiniz
	fullName := "Test Repo User"

	// 1) CreateUser
	newUser, err := repo.CreateUser(ctx, email, passwordHash, fullName)
	require.NoError(t, err, "CreateUser hata vermemeli")
	require.NotNil(t, newUser)
	assert.Equal(t, email, newUser.Email, "CreateUser’daki e-posta doğru olmalı")
	// ID değeri otomatik üretildiği için boş olamaz
	assert.NotEmpty(t, newUser.ID.String(), "Yeni kullanıcının ID’si dolu olmalı")
	// Bazı alanların null kontrolü
	assert.Equal(t, true, newUser.IsActive, "Yeni kullanıcı varsayılan olarak aktif olmalı")
	assert.False(t, newUser.EmailVerified, "Yeni kullanıcı e-posta doğrulanmamış olmalı")

	// 2) GetUserByEmail
	fetchedUserInfo, fetchedHash, fetchedActive, err := repo.GetUserByEmail(ctx, email)
	require.NoError(t, err, "GetUserByEmail hata vermemeli")
	require.NotNil(t, fetchedUserInfo)
	assert.Equal(t, email, fetchedUserInfo.Email, "GetUserByEmail ile dönen e-posta eşleşmeli")
	assert.Equal(t, fetchedActive, true, "GetUserByEmail ile dönen isActive doğru olmalı")
	// returned hash testDB’de saklanan parça ile aynı string formatında olmalı
	assert.Equal(t, passwordHash, fetchedHash, "GetUserByEmail’daki hash, CreateUser’a gönderilen ile eşleşmeli (test DB için dummy)")

	// 3) Rolleri test et
	// Eğer DB’nizde default rol vermeyen bir yapı varsa testte burada conflict olabilir;
	// biz dummy veride varsayılan “passenger” ekliyoruz.
	assert.Contains(t, fetchedUserInfo.Roles, "passenger", "Default role list içinde 'passenger' bulunmalı")
}

func TestGetUserByID_NotFound(t *testing.T) {
	if testDB == nil {
		t.Skip("TEST_DATABASE_URL ayarlı değil; repository testleri atlanıyor.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := repository.NewUserRepo(testDB)

	// Geçersiz bir UUID ile sorgulayalım (DB’da yok)
	randomID := uuid.New()
	userInfo, err := repo.GetUserByID(ctx, randomID)
	require.Error(t, err, "GetUserByID bulunamayan ID için hata döndürmeli")
	assert.Nil(t, userInfo, "UserInfo nil olmalı bulunamazken")
}

func TestStoreAndGetRefreshToken(t *testing.T) {
	if testDB == nil {
		t.Skip("TEST_DATABASE_URL ayarlı değil; repository testleri atlanıyor.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := repository.NewUserRepo(testDB)

	// Önce bir kullanıcı oluşturup ID’sini alalım
	email := "rtoken_" + uuid.NewString()[:8] + "@example.com"
	fullName := "Refresh Test User"
	passwordHash := "dummy"

	createdUser, err := repo.CreateUser(ctx, email, passwordHash, fullName)
	require.NoError(t, err)

	// Rastgele bir tokenHash ve expiry
	tokenHash := uuid.NewString()
	expiresAt := time.Now().Add(1 * time.Hour)

	err = repo.StoreRefreshToken(ctx, createdUser.ID, tokenHash, expiresAt)
	require.NoError(t, err, "StoreRefreshToken hata vermemeli")

	rt, err := repo.GetRefreshTokenByHash(ctx, tokenHash)
	require.NoError(t, err, "GetRefreshTokenByHash hata vermemeli")
	require.NotNil(t, rt)
	assert.Equal(t, tokenHash, rt.TokenHash, "TokenHash eşleşmeli")
	assert.Equal(t, createdUser.ID, rt.UserID, "UserID eşleşmeli")
}

func TestRevokeRefreshTokenAndRevocation(t *testing.T) {
	if testDB == nil {
		t.Skip("TEST_DATABASE_URL ayarlı değil; repository testleri atlanıyor.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	repo := repository.NewUserRepo(testDB)

	// Yeni bir kullanıcı oluştur
	email := "rev_" + uuid.NewString()[:8] + "@example.com"
	passwordHash := "dummy"
	fullName := "Revoke Test User"

	createdUser, err := repo.CreateUser(ctx, email, passwordHash, fullName)
	require.NoError(t, err)

	// Yeni bir token
	tokenHash := uuid.NewString()
	expiresAt := time.Now().Add(1 * time.Hour)
	require.NoError(t, repo.StoreRefreshToken(ctx, createdUser.ID, tokenHash, expiresAt))

	// Önce başarılı bulunmalı
	rt, err := repo.GetRefreshTokenByHash(ctx, tokenHash)
	require.NoError(t, err)
	assert.False(t, rt.Revoked, "Revoked false olmalı ilk başta")

	// Revoke
	require.NoError(t, repo.RevokeRefreshTokenByHash(ctx, tokenHash))

	// Artık bulunmamalı (çünkü revoked = TRUE)
	_, err = repo.GetRefreshTokenByHash(ctx, tokenHash)
	require.Error(t, err, "Revoked token GetRefreshTokenByHash’da bulunmamalı")
}
