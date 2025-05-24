-- migrations/000004_add_email_verification_tokens_table.up.sql
CREATE TABLE IF NOT EXISTS auth.email_verification_tokens (
    token_hash TEXT PRIMARY KEY, -- Token'ın hash'i saklanacak
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL, -- Hangi e-postanın doğrulandığı (ileride e-posta değişikliği için gerekebilir)
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT FALSE -- Token kullanıldı mı?
);

CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id ON auth.email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_email ON auth.email_verification_tokens(email);