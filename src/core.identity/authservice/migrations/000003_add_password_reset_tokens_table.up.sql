-- migrations/000003_add_password_reset_tokens_table.up.sql
CREATE TABLE IF NOT EXISTS auth.password_reset_tokens (
    token_hash TEXT PRIMARY KEY, -- Token'ın kendisi değil, hash'i saklanacak
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed BOOLEAN NOT NULL DEFAULT FALSE -- Token kullanıldı mı?
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON auth.password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON auth.password_reset_tokens(expires_at);