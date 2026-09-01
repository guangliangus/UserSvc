-- =============================================================================
-- 0001 · identity schema: user profiles, login identities, device sessions, outbox.
--
-- Run by hand (decision 14): DDL first, code second. Neither application startup nor the
-- deployment pipeline ever changes the database. This script is idempotent and re-runnable.
-- After changing an entity or an EF configuration, generate the reference SQL with
--   dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
-- then extract the delta into a new numbered script.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS identity;

-- ----------------------------------------------------------------- users
CREATE TABLE IF NOT EXISTS identity.users
(
    id                     SERIAL PRIMARY KEY,
    status                 TEXT        NOT NULL DEFAULT 'PENDING',
    first_name             TEXT        NOT NULL DEFAULT '',
    last_name              TEXT        NOT NULL DEFAULT '',
    nickname               TEXT        NOT NULL DEFAULT '',
    avatar                 TEXT        NOT NULL DEFAULT '',
    residence_country_code TEXT        NOT NULL DEFAULT '',
    password_algo          TEXT        NOT NULL DEFAULT '',
    password_hash          TEXT        NOT NULL DEFAULT '',
    birth_date_hash        TEXT        NOT NULL DEFAULT '',
    birth_date_ciphertext  TEXT        NOT NULL DEFAULT '',
    birth_date_key_version TEXT        NOT NULL DEFAULT '',
    last_login_at          TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by             TEXT        NOT NULL DEFAULT '',
    updated_by             TEXT        NOT NULL DEFAULT ''
);

COMMENT ON COLUMN identity.users.status IS 'PENDING | ACTIVE | DISABLED | DELETED';
COMMENT ON COLUMN identity.users.password_algo IS 'BCRYPT | ARGON2ID';
COMMENT ON COLUMN identity.users.birth_date_hash IS 'Blind index: HMAC-SHA256(birth date, pepper)';
COMMENT ON COLUMN identity.users.birth_date_key_version IS 'DEK version used to encrypt; the rotation job filters on it';

CREATE INDEX IF NOT EXISTS ix_users_birth_date_hash ON identity.users (birth_date_hash);

-- ------------------------------------------------------- user_identities
CREATE TABLE IF NOT EXISTS identity.user_identities
(
    id                     SERIAL PRIMARY KEY,
    user_id                INTEGER     NOT NULL REFERENCES identity.users (id),
    identity_type          TEXT        NOT NULL,
    identifier_hash        TEXT        NOT NULL,
    identifier_ciphertext  TEXT        NOT NULL DEFAULT '',
    identifier_key_version TEXT        NOT NULL DEFAULT '',
    status                 TEXT        NOT NULL DEFAULT 'ACTIVE',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by             TEXT        NOT NULL DEFAULT '',
    updated_by             TEXT        NOT NULL DEFAULT ''
);

COMMENT ON COLUMN identity.user_identities.identity_type IS
    'PHONE | EMAIL | WECHAT | WECHAT_MINI | FIREBASE | LINE | PASSKEY';
COMMENT ON COLUMN identity.user_identities.identifier_hash IS 'Blind index carrying the unique index; the plaintext is never stored';

-- Unique but revocable: once unbound, the same phone number can be attached to another account.
CREATE UNIQUE INDEX IF NOT EXISTS ix_user_identities_identity_type_identifier_hash
    ON identity.user_identities (identity_type, identifier_hash) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS ix_user_identities_user_id
    ON identity.user_identities (user_id);

-- --------------------------------------------------------- user_sessions
CREATE TABLE IF NOT EXISTS identity.user_sessions
(
    id                         SERIAL PRIMARY KEY,
    session_id                 TEXT        NOT NULL,
    user_id                    INTEGER     NOT NULL,
    device_id                  TEXT        NOT NULL,
    device_name                TEXT        NOT NULL DEFAULT '',
    platform                   TEXT        NOT NULL,
    app_version                TEXT        NOT NULL DEFAULT '',
    ip_address                 TEXT        NOT NULL DEFAULT '',
    user_agent                 TEXT        NOT NULL DEFAULT '',
    status                     TEXT        NOT NULL DEFAULT 'ACTIVE',
    revoked_by                 TEXT        NOT NULL DEFAULT '',
    current_refresh_token_hash TEXT        NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    refresh_expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at                 TIMESTAMPTZ
);

COMMENT ON TABLE  identity.user_sessions IS 'One sign-in on one device = one row = one refresh token family chain';
COMMENT ON COLUMN identity.user_sessions.session_id IS 'The access token sid claim; server-generated and the only trustworthy session id';
COMMENT ON COLUMN identity.user_sessions.device_id IS 'Client-reported and forgeable: display and de-duplication only, never a security boundary';
COMMENT ON COLUMN identity.user_sessions.status IS 'ACTIVE | REVOKED';
COMMENT ON COLUMN identity.user_sessions.revoked_by IS
    'SELF | OTHER_DEVICE | SUPERSEDED | PASSWORD_CHANGE | ADMIN | TOKEN_REPLAY';
COMMENT ON COLUMN identity.user_sessions.last_seen_at IS 'Updated on token refresh only; writing on every request is write amplification';

CREATE UNIQUE INDEX IF NOT EXISTS ix_user_sessions_session_id
    ON identity.user_sessions (session_id);
CREATE INDEX IF NOT EXISTS ix_user_sessions_user_id
    ON identity.user_sessions (user_id);
-- One user on one device may hold at most one active session.
CREATE UNIQUE INDEX IF NOT EXISTS ix_user_sessions_user_id_device_id
    ON identity.user_sessions (user_id, device_id) WHERE status = 'ACTIVE';
-- Refresh looks a session up by its current hash; indexing active rows keeps revoked ones out.
CREATE INDEX IF NOT EXISTS ix_user_sessions_current_refresh_token_hash
    ON identity.user_sessions (current_refresh_token_hash) WHERE status = 'ACTIVE';

-- -------------------------------------------------------- outbox_messages
-- Decision 16: rows here are inserted in the same transaction as the business row. This is the
-- one atomic point in the whole chain.
CREATE TABLE IF NOT EXISTS identity.outbox_messages
(
    id            SERIAL PRIMARY KEY,
    message_id    TEXT        NOT NULL,
    event_name    TEXT        NOT NULL,
    payload       TEXT        NOT NULL,
    trace_parent  TEXT        NOT NULL DEFAULT '',
    occurred_at   TIMESTAMPTZ NOT NULL,
    dispatched_at TIMESTAMPTZ,
    attempts      INTEGER     NOT NULL DEFAULT 0,
    last_error    TEXT        NOT NULL DEFAULT ''
);

COMMENT ON COLUMN identity.outbox_messages.event_name IS 'Published contract name, for example user.session-revoked.v1';

CREATE UNIQUE INDEX IF NOT EXISTS ix_outbox_messages_message_id
    ON identity.outbox_messages (message_id);
-- 投递器取件索引：只覆盖未投递行，投递完成后自然退出索引。
CREATE INDEX IF NOT EXISTS ix_outbox_messages_occurred_at_id
    ON identity.outbox_messages (occurred_at, id) WHERE dispatched_at IS NULL;
