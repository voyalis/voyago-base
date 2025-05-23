CREATE SCHEMA IF NOT EXISTS auth;

-- Kullanıcılar Tablosu
CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    email_verified BOOLEAN DEFAULT FALSE,
    last_sign_in_at TIMESTAMPTZ, -- Son giriş zamanı
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth.users (email);

-- Roller Tablosu
CREATE TABLE IF NOT EXISTS auth.roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL, -- örn: passenger, driver, admin
    description TEXT
);

-- Kullanıcı-Rol İlişki Tablosu
CREATE TABLE IF NOT EXISTS auth.user_roles (
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES auth.roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX IF NOT EXISTS idx_auth_user_roles_user_id ON auth.user_roles (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_user_roles_role_id ON auth.user_roles (role_id);

-- Refresh Token'lar Tablosu
CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Token'ın kendi ID'si
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL, -- Güvenlik için token'ın hash'i saklanmalı
    parent_id UUID REFERENCES auth.refresh_tokens(id) ON DELETE SET NULL, -- Token rotasyonu için bir önceki token'ın ID'si (opsiyonel)
    revoked BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON auth.refresh_tokens (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON auth.refresh_tokens (token_hash); -- Eğer hash'ler benzersiz olacaksa

-- Başlangıç Rolleri
INSERT INTO auth.roles (name, description) VALUES
('passenger', 'Regular passenger user'),
('driver', 'Verified driver user'),
('admin', 'System administrator')
ON CONFLICT (name) DO NOTHING;