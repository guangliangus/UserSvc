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
    id                     SERIAL NOT NULL,
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
    updated_by             TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_users PRIMARY KEY (id)
);

COMMENT ON COLUMN identity.users.status IS 'PENDING | ACTIVE | DISABLED | DELETED';
COMMENT ON COLUMN identity.users.password_algo IS 'BCRYPT | ARGON2ID';
COMMENT ON COLUMN identity.users.birth_date_hash IS 'Blind index: HMAC-SHA256(birth date, pepper)';
COMMENT ON COLUMN identity.users.birth_date_key_version IS 'DEK version used to encrypt; the rotation job filters on it';

CREATE INDEX IF NOT EXISTS ix_users_birth_date_hash ON identity.users (birth_date_hash);

-- ------------------------------------------------------- user_identities
CREATE TABLE IF NOT EXISTS identity.user_identities
(
    id                     SERIAL NOT NULL,
    user_id                INTEGER     NOT NULL REFERENCES identity.users (id),
    identity_type          TEXT        NOT NULL,
    identifier_hash        TEXT        NOT NULL,
    identifier_ciphertext  TEXT        NOT NULL DEFAULT '',
    identifier_key_version TEXT        NOT NULL DEFAULT '',
    status                 TEXT        NOT NULL DEFAULT 'ACTIVE',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by             TEXT        NOT NULL DEFAULT '',
    updated_by             TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_user_identities PRIMARY KEY (id)
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
--
-- user_id ALONE IDENTIFIES NOBODY. It holds an id from one of two tables that number their rows
-- independently - identity.users (consumers) and iam.backend_users (back office) - so realm is the
-- other half of the subject and every index keyed on the subject leads with it. See the realm
-- column below.
--
-- current_refresh_token_hash and refresh_expires_at are NOT created here any more. 0002 drops both
-- (OpenIddict owns refresh tokens now) and has been applied everywhere, so creating them here only
-- meant a fresh database grew two columns for one script's worth of time, the generated EF script
-- reported them as gate-04 drift, and - because CREATE TABLE IF NOT EXISTS skips an existing table
-- while the CREATE INDEX below did not skip a missing column - re-running this script against any
-- database that had had 0002 applied failed outright. 0002's DROP ... IF EXISTS statements stay
-- where they are as the record of the change and are now no-ops.
CREATE TABLE IF NOT EXISTS identity.user_sessions
(
    id                         SERIAL      NOT NULL,
    session_id                 TEXT        NOT NULL,
    user_id                    INTEGER     NOT NULL,
    realm                      TEXT        NOT NULL,
    device_id                  TEXT        NOT NULL,
    device_name                TEXT        NOT NULL DEFAULT '',
    platform                   TEXT        NOT NULL,
    app_version                TEXT        NOT NULL DEFAULT '',
    ip_address                 TEXT        NOT NULL DEFAULT '',
    user_agent                 TEXT        NOT NULL DEFAULT '',
    status                     TEXT        NOT NULL DEFAULT 'ACTIVE',
    revoked_by                 TEXT        NOT NULL DEFAULT '',
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at                 TIMESTAMPTZ,
    CONSTRAINT pk_user_sessions PRIMARY KEY (id),
    CONSTRAINT chk_user_sessions_realm CHECK (realm IN ('CONSUMER', 'BACKOFFICE'))
);

-- ----------------------------------------------- user_sessions · realm
-- NO DEFAULT ON THE COLUMN, and that is the whole point of the three steps below.
--
-- A default is the database quietly answering a question the writer failed to answer, which is the
-- bug being fixed one layer down: the reason this column exists is that a session was creatable
-- without saying whose it was. With no default, an INSERT that omits realm fails on the NOT NULL
-- instead of being labelled CONSUMER and looking correct. The domain aggregate cannot be
-- constructed without a realm either; this is the same rule where it can actually be enforced.
--
-- A default would also be needed only to make the column addable to a populated table, and it is
-- not: adding it NULLABLE costs nothing (PostgreSQL rewrites no rows), the existing rows are then
-- labelled deliberately, and SET NOT NULL closes it. Nothing is ever labelled by omission.
ALTER TABLE identity.user_sessions
    ADD COLUMN IF NOT EXISTS realm TEXT;

-- Label rows written before the column existed, FROM EVIDENCE AND PER ROW rather than in bulk.
-- ADD COLUMN ... DEFAULT 'CONSUMER' would have stamped every existing row, and on the live database
-- nine of the twenty-two were back-office sessions (read 2026-09-02). A mislabelled row does not
-- fail loudly - a refresh only looks a session up by its sid, which is realm-free - it just stops
-- being manageable by its owner and becomes revocable by a stranger who shares its integer.
--
-- The evidence is the OpenIddict authorization the session already points at: a back-office grant
-- asks for the 'backoffice' scope and a consumer device login does not. Only NULL rows are touched,
-- so a re-run cannot relabel a row the application has since written itself.
--
-- The guard is for script order. On a fresh database 0002 has not run yet, so neither the openiddict
-- schema nor user_sessions.authorization_id exists - and there is nothing to label either, because
-- the table was just created. The UPDATE is inside the IF for that reason: PL/pgSQL parses a
-- statement when it first reaches it, so on a fresh database the reference to authorization_id is
-- never parsed. Where the openiddict schema does exist, 0002 has run and so has that column.
DO $realm_backfill$
BEGIN
    IF to_regclass('openiddict.openiddict_authorizations') IS NULL THEN
        RETURN;
    END IF;

    UPDATE identity.user_sessions s
       SET realm = CASE
                       WHEN a.scopes LIKE '%"backoffice"%' THEN 'BACKOFFICE'
                       ELSE 'CONSUMER'
                   END
      FROM openiddict.openiddict_authorizations a
     WHERE s.realm IS NULL
       AND a.id::text = s.authorization_id;
END
$realm_backfill$;

-- A row whose authorization is gone carries no evidence of its realm, so its realm is not guessed
-- at: it is revoked. That puts it outside every partial index and outside every active-session
-- query, so the label it has to carry can no longer be read by any code path, and it costs its
-- holder one sign-in. Guessing instead would hand somebody a stranger's device to sign out.
UPDATE identity.user_sessions
   SET realm      = 'CONSUMER',
       status     = 'REVOKED',
       revoked_by = 'ADMIN',
       revoked_at = COALESCE(revoked_at, now())
 WHERE realm IS NULL;

ALTER TABLE identity.user_sessions
    ALTER COLUMN realm SET NOT NULL;

-- ADD CONSTRAINT has no IF NOT EXISTS; a fresh database already carries it from CREATE TABLE.
DO $realm_check$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'chk_user_sessions_realm'
           AND conrelid = 'identity.user_sessions'::regclass
    ) THEN
        ALTER TABLE identity.user_sessions
            ADD CONSTRAINT chk_user_sessions_realm CHECK (realm IN ('CONSUMER', 'BACKOFFICE'));
    END IF;
END
$realm_check$;

COMMENT ON TABLE  identity.user_sessions IS 'One sign-in on one device = one row = one refresh token family chain';
COMMENT ON COLUMN identity.user_sessions.session_id IS 'The access token sid claim; server-generated and the only trustworthy session id';
COMMENT ON COLUMN identity.user_sessions.device_id IS 'Client-reported and forgeable: display and de-duplication only, never a security boundary';
COMMENT ON COLUMN identity.user_sessions.user_id IS 'Subject id within realm; identity.users.id or iam.backend_users.id';
COMMENT ON COLUMN identity.user_sessions.realm IS 'CONSUMER | BACKOFFICE';
COMMENT ON COLUMN identity.user_sessions.status IS 'ACTIVE | REVOKED';
COMMENT ON COLUMN identity.user_sessions.revoked_by IS
    'SELF | OTHER_DEVICE | SUPERSEDED | PASSWORD_CHANGE | ADMIN | TOKEN_REPLAY';
COMMENT ON COLUMN identity.user_sessions.last_seen_at IS 'Updated on token refresh only; writing on every request is write amplification';

-- Realm-free on purpose, and the only index here that is. A session_id is a server-generated GUID
-- and this index is what makes it resolve to exactly one row across both planes; per-realm
-- uniqueness would let one sid name two sessions, and the refresh, replay and sign-out paths hold
-- nothing but the sid.
CREATE UNIQUE INDEX IF NOT EXISTS ix_user_sessions_session_id
    ON identity.user_sessions (session_id);

-- The subject's whole session history, active and revoked - the one read the partial index below
-- cannot serve. Realm leads: both columns are always equality predicates, so its two distinct
-- values cost nothing in that position, and a user_id-only prefix is exactly the cross-realm
-- lookup this column exists to remove.
DROP INDEX IF EXISTS identity.ix_user_sessions_user_id;
CREATE INDEX IF NOT EXISTS ix_user_sessions_realm_user_id
    ON identity.user_sessions (realm, user_id);

-- One subject on one device may hold at most one active session - and one subject is
-- (realm, user_id). Keyed on user_id alone this index made consumer 100 and back-office 100
-- collide from the same device_id, so whichever of them signed in second could not sign in at all;
-- the device-limit eviction and "sign out my other devices" both walk it and both crossed planes.
DROP INDEX IF EXISTS identity.ix_user_sessions_user_id_device_id;
CREATE UNIQUE INDEX IF NOT EXISTS ix_user_sessions_realm_user_id_device_id
    ON identity.user_sessions (realm, user_id, device_id) WHERE status = 'ACTIVE';

-- -------------------------------------------------------- outbox_messages
-- Decision 16: rows here are inserted in the same transaction as the business row. This is the
-- one atomic point in the whole chain.
CREATE TABLE IF NOT EXISTS identity.outbox_messages
(
    id            SERIAL NOT NULL,
    message_id    TEXT        NOT NULL,
    event_name    TEXT        NOT NULL,
    payload       TEXT        NOT NULL,
    trace_parent  TEXT        NOT NULL DEFAULT '',
    occurred_at   TIMESTAMPTZ NOT NULL,
    dispatched_at TIMESTAMPTZ,
    attempts      INTEGER     NOT NULL DEFAULT 0,
    last_error    TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_outbox_messages PRIMARY KEY (id)
);

COMMENT ON COLUMN identity.outbox_messages.event_name IS 'Published contract name, for example user.session-revoked.v1';

CREATE UNIQUE INDEX IF NOT EXISTS ix_outbox_messages_message_id
    ON identity.outbox_messages (message_id);
-- 投递器取件索引：只覆盖未投递行，投递完成后自然退出索引。
CREATE INDEX IF NOT EXISTS ix_outbox_messages_occurred_at_id
    ON identity.outbox_messages (occurred_at, id) WHERE dispatched_at IS NULL;
