-- migrations/000002_create_refresh_tokens_table.up.sql
CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL, -- SHA256 hash'i için 64 karakter yeterli olabilir, ama biraz pay bırakalım
    parent_id UUID REFERENCES auth.refresh_tokens(id) ON DELETE SET NULL, -- Token rotasyonu için bir önceki token'ın ID'si
    revoked BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON auth.refresh_tokens (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON auth.refresh_tokens (token_hash);