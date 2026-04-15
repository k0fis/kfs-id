-- V2__create_user_data.sql

CREATE TABLE user_data (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app           VARCHAR(64) NOT NULL,
    data_key      VARCHAR(128) NOT NULL,
    data          TEXT NOT NULL,
    content_type  VARCHAR(128) NOT NULL DEFAULT 'application/json',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, app, data_key)
);

CREATE INDEX idx_user_data_user_app ON user_data (user_id, app);
