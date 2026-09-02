-- =============================================================================
-- 0004 · iam schema: back-office (B-end) accounts and their login identities.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- Column order, types, constraint names and index names are byte-matched to what
--   dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
-- emits, so CI gate 04 diffs clean.
--
-- WHY A SECOND SCHEMA. Back-office accounts are a different bounded context from consumer
-- identities: different lifecycle, different audience, different id space. The same mailbox can be
-- a customer and an operator at once, and those are two accounts - collapsing them would mean
-- disabling an employee also disables their personal booking account. There is deliberately NO
-- foreign key between iam.* and identity.*, so nothing can join the two planes back together by
-- accident.
--
-- ORDERING: this script must run BEFORE any script that creates iam.tenant_members, which
-- references iam.backend_users(id).
--
-- ONE SHAPE HERE DEPARTS FROM THE TEAM'S DDL CONVENTIONS, and it is the nullability, not the
-- types. Most string columns are nullable rather than NOT NULL DEFAULT '': see db/README.md, which
-- argues it column by column. In short, NULL is load-bearing on password_hash ("this account has
-- no password door", not "the empty password") and the CLR properties are `string?` to match, so
-- closing the nullability is a data migration plus a domain change, not a spelling fix.
--
-- The five varchar(n) columns this header used to justify - status, identity_type, provider,
-- identifier_hash, key_version - are now TEXT, like every other string in this database. The
-- justification was "existing rows are the constraint", and it was false: iam is this service's
-- own schema, every row in it was written by this service (checked 2026-09-02: all 11 accounts and
-- all 3 identities carry created_by 'probe'/'system' and key_version 'dev'), the Go service's rows
-- live in uam and nothing joins the two planes, and 0001 created the same five concepts on the
-- consumer side - identity.user_identities - as TEXT from the start.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS iam;

-- ------------------------------------------------------------- backend_users
CREATE TABLE IF NOT EXISTS iam.backend_users
(
    id             SERIAL             NOT NULL,
    password_hash  TEXT,
    first_name     TEXT,
    last_name      TEXT,
    nickname       TEXT,
    avatar         TEXT,
    staff_code     TEXT,
    dept_no        TEXT,
    dept_name      TEXT,
    status         TEXT               NOT NULL DEFAULT 'PENDING',
    origin         TEXT               NOT NULL DEFAULT 'INTERNAL',
    token_version  INTEGER            NOT NULL DEFAULT 0,
    is_super_admin BOOLEAN            NOT NULL DEFAULT FALSE,
    last_login_at  TIMESTAMPTZ,
    created_at     TIMESTAMPTZ        NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ        NOT NULL DEFAULT now(),
    created_by     TEXT,
    updated_by     TEXT,
    CONSTRAINT pk_backend_users PRIMARY KEY (id),
    CONSTRAINT chk_backend_users_origin CHECK (origin IN ('INTERNAL', 'EXTERNAL')),
    CONSTRAINT chk_backend_users_status CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED'))
);

COMMENT ON TABLE  iam.backend_users IS
    'Back-office (B-end) accounts, physically separate from the consumer identity.users table';
COMMENT ON COLUMN iam.backend_users.password_hash IS
    'Argon2id PHC string; NULL for an account that has only ever signed in through the staff directory';
COMMENT ON COLUMN iam.backend_users.status IS 'PENDING | ACTIVE | DISABLED';
COMMENT ON COLUMN iam.backend_users.origin IS
    'INTERNAL = group staff, subject to the corporate email-domain gate; EXTERNAL = B2B partner, exempt';
COMMENT ON COLUMN iam.backend_users.token_version IS
    'Baseline for the token version claim; +1 instantly invalidates every access token this account holds';
COMMENT ON COLUMN iam.backend_users.is_super_admin IS
    'Platform super administrator: an identity (all permissions, all menus, both global data scopes), '
    'not a data breadth. Written only by the dedicated guarded statements';

CREATE INDEX IF NOT EXISTS idx_backend_users_status ON iam.backend_users (status);

-- -------------------------------------------------------- backend_identities
CREATE TABLE IF NOT EXISTS iam.backend_identities
(
    id                    SERIAL                NOT NULL,
    user_id               INTEGER               NOT NULL,
    identity_type         TEXT                  NOT NULL,
    provider              TEXT                  NOT NULL DEFAULT '',
    provider_uid          TEXT,
    identifier_hash       TEXT                  NOT NULL,
    identifier_ciphertext TEXT                  NOT NULL,
    identifier_masked     TEXT                  NOT NULL,
    key_version           TEXT                  NOT NULL,
    provider_details      JSONB,
    status                TEXT                  NOT NULL DEFAULT 'ACTIVE',
    created_at            TIMESTAMPTZ           NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ           NOT NULL DEFAULT now(),
    created_by            TEXT,
    updated_by            TEXT,
    CONSTRAINT pk_backend_identities PRIMARY KEY (id),
    CONSTRAINT chk_backend_identity_type CHECK (identity_type IN ('email', 'phone', 'OTP')),
    CONSTRAINT fk_backend_identities_backend_users_user_id
        FOREIGN KEY (user_id) REFERENCES iam.backend_users (id) ON DELETE CASCADE
);

COMMENT ON TABLE  iam.backend_identities IS
    'Back-office login identities. Uniqueness is scoped to this table: the same address may also '
    'exist independently as a consumer identity';
COMMENT ON COLUMN iam.backend_identities.identity_type IS 'email | phone | OTP (employee number)';
COMMENT ON COLUMN iam.backend_identities.identifier_hash IS
    'Blind index: HMAC-SHA256 of the normalized identifier. The partial unique indexes live on it';
COMMENT ON COLUMN iam.backend_identities.identifier_masked IS
    'Display fallback when the ciphertext cannot be decrypted; never a lookup key';
COMMENT ON COLUMN iam.backend_identities.key_version IS
    'DEK version the ciphertext was written with, so a rotation job can find the rows it still owes';
COMMENT ON COLUMN iam.backend_identities.status IS 'ACTIVE | DISABLED; only ACTIVE rows are unique';

CREATE INDEX IF NOT EXISTS idx_backend_identity_user ON iam.backend_identities (user_id);

-- One account per address, per kind of address. Filtered on ACTIVE so an identity stays revocable
-- and its address later reclaimable.
CREATE UNIQUE INDEX IF NOT EXISTS idx_backend_identity_unique_email_active
    ON iam.backend_identities (identity_type, identifier_hash)
    WHERE status = 'ACTIVE' AND identity_type = 'email';
CREATE UNIQUE INDEX IF NOT EXISTS idx_backend_identity_unique_phone_active
    ON iam.backend_identities (identity_type, identifier_hash)
    WHERE status = 'ACTIVE' AND identity_type = 'phone';
CREATE UNIQUE INDEX IF NOT EXISTS idx_backend_identity_unique_otp_active
    ON iam.backend_identities (identity_type, identifier_hash)
    WHERE status = 'ACTIVE' AND identity_type = 'OTP';

-- One address per account, per kind of address. Neither family implies the other: without the
-- first, two accounts could claim one mailbox; without this one, "the account's email address"
-- would stop being a well-defined thing for password reset to mail a code to.
CREATE UNIQUE INDEX IF NOT EXISTS idx_backend_identity_user_email_active
    ON iam.backend_identities (user_id, identity_type)
    WHERE status = 'ACTIVE' AND identity_type = 'email';
CREATE UNIQUE INDEX IF NOT EXISTS idx_backend_identity_user_phone_active
    ON iam.backend_identities (user_id, identity_type)
    WHERE status = 'ACTIVE' AND identity_type = 'phone';
CREATE UNIQUE INDEX IF NOT EXISTS idx_backend_identity_user_otp_active
    ON iam.backend_identities (user_id, identity_type)
    WHERE status = 'ACTIVE' AND identity_type = 'OTP';

-- ================================================ varchar(n) -> text, for databases created before
--
-- CREATE TABLE above is the shape a fresh database gets. This block is how a database created while
-- these five columns were CHARACTER VARYING(n) reaches the same shape, and it is written to be a
-- complete no-op once it has run.
--
-- WHAT ALTER TYPE ACTUALLY DOES HERE, measured on a copy of this schema (PostgreSQL 18.1):
--   * No table rewrite. varchar(n) -> text is binary coercible, so every row's relfilenode was
--     unchanged - the conversion is a catalogue update, not a copy.
--   * Indexes whose PREDICATE mentions a converted column ARE rebuilt: the six partial unique
--     indexes on identity_type all took new relfilenodes, because their stored predicate changes
--     from ((identity_type)::text = 'email'::text) to (identity_type = 'email'::text). The plain
--     btree on backend_users.status was NOT rebuilt. Nothing to do about either, but it is why
--     this takes an ACCESS EXCLUSIVE lock and is not free on a large table.
--   * A column DEFAULT keeps its OLD type: 'PENDING'::character varying survives the conversion
--     and then differs from the 'PENDING'::text a fresh database has. Re-set below.
--   * A CHECK constraint survives and keeps working, but is re-derived as
--     ARRAY[('email'::character varying)::text, ...] - same meaning, different text from a fresh
--     database's. Dropped and re-added below, so a converted database and a fresh one produce
--     identical constraint definitions and gate 04 has nothing to report.
DO $iam_varchar_to_text$
DECLARE
    target RECORD;
BEGIN
    FOR target IN
        SELECT *
          FROM (VALUES
                    ('backend_users', 'status'),
                    ('backend_identities', 'identity_type'),
                    ('backend_identities', 'provider'),
                    ('backend_identities', 'identifier_hash'),
                    ('backend_identities', 'key_version')
               ) AS t (table_name, column_name)
    LOOP
        IF EXISTS (SELECT 1
                     FROM information_schema.columns
                    WHERE table_schema = 'iam'
                      AND table_name = target.table_name
                      AND column_name = target.column_name
                      AND data_type = 'character varying') THEN
            EXECUTE format(
                'ALTER TABLE iam.%I ALTER COLUMN %I TYPE TEXT',
                target.table_name, target.column_name);
        END IF;
    END LOOP;
END
$iam_varchar_to_text$;

-- Unconditional and idempotent: re-declaring the same default is a catalogue write and nothing
-- more. On a converted database it replaces 'PENDING'::character varying with 'PENDING'::text; on a
-- fresh one it replaces the value with itself.
ALTER TABLE iam.backend_users      ALTER COLUMN status   SET DEFAULT 'PENDING';
ALTER TABLE iam.backend_identities ALTER COLUMN provider SET DEFAULT '';

-- The CHECK constraints are the thing that actually enforces these value sets, so they are kept -
-- only their stored text is normalised. Guarded on that text, so this runs once.
DO $iam_check_to_text$
BEGIN
    IF EXISTS (SELECT 1
                 FROM pg_constraint
                WHERE conname = 'chk_backend_users_status'
                  AND conrelid = 'iam.backend_users'::regclass
                  AND pg_get_constraintdef(oid) LIKE '%character varying%') THEN
        ALTER TABLE iam.backend_users DROP CONSTRAINT chk_backend_users_status;
        ALTER TABLE iam.backend_users
            ADD CONSTRAINT chk_backend_users_status CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED'));
    END IF;

    IF EXISTS (SELECT 1
                 FROM pg_constraint
                WHERE conname = 'chk_backend_identity_type'
                  AND conrelid = 'iam.backend_identities'::regclass
                  AND pg_get_constraintdef(oid) LIKE '%character varying%') THEN
        ALTER TABLE iam.backend_identities DROP CONSTRAINT chk_backend_identity_type;
        ALTER TABLE iam.backend_identities
            ADD CONSTRAINT chk_backend_identity_type CHECK (identity_type IN ('email', 'phone', 'OTP'));
    END IF;
END
$iam_check_to_text$;
