-- =============================================================================
-- 0002 · OpenIddict token storage + the user_sessions columns that move with it.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- Generated from the model with
--   dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
-- and hand-edited only to add IF NOT EXISTS; the object and constraint names below must stay
-- byte-identical to that output or CI gate 04 reports permanent drift.
-- =============================================================================

-- OpenIddict's tables live in their own schema: protocol plumbing, not identity data, so grants
-- and backups can be handled separately.
CREATE SCHEMA IF NOT EXISTS openiddict;

-- ------------------------------------------------- openiddict_applications
-- uuid keys, not the default string ones (37 bytes in every foreign key) and not a 4-byte
-- sequence: OpenIddict writes two token rows per token request, so at a 10-minute access-token
-- lifetime that is ~144 rows per device per day.
CREATE TABLE IF NOT EXISTS openiddict.openiddict_applications
(
    id                        UUID NOT NULL,
    application_type          TEXT,
    client_id                 TEXT,
    client_secret             TEXT,
    client_type               TEXT,
    concurrency_token         TEXT,
    consent_type              TEXT,
    display_name              TEXT,
    display_names             TEXT,
    json_web_key_set          TEXT,
    permissions               TEXT,
    post_logout_redirect_uris TEXT,
    properties                TEXT,
    redirect_uris             TEXT,
    requirements              TEXT,
    settings                  TEXT,
    CONSTRAINT pk_openiddict_applications PRIMARY KEY (id)
);

-- ------------------------------------------------------- openiddict_scopes
CREATE TABLE IF NOT EXISTS openiddict.openiddict_scopes
(
    id                UUID NOT NULL,
    concurrency_token TEXT,
    description       TEXT,
    descriptions      TEXT,
    display_name      TEXT,
    display_names     TEXT,
    name              TEXT,
    properties        TEXT,
    resources         TEXT,
    CONSTRAINT pk_openiddict_scopes PRIMARY KEY (id)
);

-- ----------------------------------------------- openiddict_authorizations
-- One row per device sign-in. Every token of that session hangs off it, which is what makes
-- "revoke the chain" a single statement and what makes refresh-token replay detectable.
CREATE TABLE IF NOT EXISTS openiddict.openiddict_authorizations
(
    id                UUID NOT NULL,
    application_id    UUID,
    concurrency_token TEXT,
    creation_date     TIMESTAMPTZ,
    properties        TEXT,
    scopes            TEXT,
    status            TEXT,
    subject           TEXT,
    type              TEXT,
    CONSTRAINT pk_openiddict_authorizations PRIMARY KEY (id),
    CONSTRAINT fk_openiddict_authorizations_openiddict_applications_applicati
        FOREIGN KEY (application_id) REFERENCES openiddict.openiddict_applications (id)
);

COMMENT ON COLUMN openiddict.openiddict_authorizations.status IS 'valid | inactive | redeemed | rejected | revoked';
COMMENT ON COLUMN openiddict.openiddict_authorizations.type IS 'ad-hoc | permanent';

-- ------------------------------------------------------- openiddict_tokens
CREATE TABLE IF NOT EXISTS openiddict.openiddict_tokens
(
    id                UUID NOT NULL,
    application_id    UUID,
    authorization_id  UUID,
    concurrency_token TEXT,
    creation_date     TIMESTAMPTZ,
    expiration_date   TIMESTAMPTZ,
    payload           TEXT,
    properties        TEXT,
    redemption_date   TIMESTAMPTZ,
    reference_id      TEXT,
    status            TEXT,
    subject           TEXT,
    type              TEXT,
    CONSTRAINT pk_openiddict_tokens PRIMARY KEY (id),
    CONSTRAINT fk_openiddict_tokens_openiddict_applications_application_id
        FOREIGN KEY (application_id) REFERENCES openiddict.openiddict_applications (id),
    CONSTRAINT fk_openiddict_tokens_openiddict_authorizations_authorization_id
        FOREIGN KEY (authorization_id) REFERENCES openiddict.openiddict_authorizations (id)
);

COMMENT ON COLUMN openiddict.openiddict_tokens.status IS 'valid | inactive | redeemed | rejected | revoked';
COMMENT ON COLUMN openiddict.openiddict_tokens.redemption_date IS 'Set when the token is traded in; presenting it again after this is a replay';

CREATE UNIQUE INDEX IF NOT EXISTS ix_openiddict_applications_client_id
    ON openiddict.openiddict_applications (client_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_openiddict_scopes_name
    ON openiddict.openiddict_scopes (name);
CREATE INDEX IF NOT EXISTS ix_openiddict_authorizations_application_id_status_subject_type
    ON openiddict.openiddict_authorizations (application_id, status, subject, type);
CREATE INDEX IF NOT EXISTS ix_openiddict_tokens_application_id_status_subject_type
    ON openiddict.openiddict_tokens (application_id, status, subject, type);
CREATE INDEX IF NOT EXISTS ix_openiddict_tokens_authorization_id
    ON openiddict.openiddict_tokens (authorization_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_openiddict_tokens_reference_id
    ON openiddict.openiddict_tokens (reference_id);

-- --------------------------------------------------------- user_sessions
-- The session now records the authorization its token chain hangs off, so signing a device out
-- can kill the chain and not just the row. Backfilled to '' for rows written before this script:
-- those chains can no longer be revoked wholesale, only expired.
ALTER TABLE identity.user_sessions
    ADD COLUMN IF NOT EXISTS authorization_id TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN identity.user_sessions.authorization_id IS
    'OpenIddict authorization id; every token of this session shares it';


-- OpenIddict owns refresh tokens now, so the hand-rolled rotation columns are dead.
--
-- ORDER OF OPERATIONS: everything above is backward compatible and may be applied before the
-- code ships. The three statements below are NOT - the previous build writes
-- current_refresh_token_hash on every rotation. Run them only once no replica of that build is
-- left, which is the "add -> dual-write -> migrate -> drop" discipline in db/README.md. Until
-- they run, CI gate 04 reports these two columns as drift; that is the expected transient state.
DROP INDEX IF EXISTS identity.ix_user_sessions_current_refresh_token_hash;

ALTER TABLE identity.user_sessions
    DROP COLUMN IF EXISTS current_refresh_token_hash;
ALTER TABLE identity.user_sessions
    DROP COLUMN IF EXISTS refresh_expires_at;
