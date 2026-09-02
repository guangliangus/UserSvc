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
-- Two shapes here follow the live database rather than the team's own DDL preferences, because
-- existing rows are the constraint:
--   * status / identity_type / provider / identifier_hash / key_version are varchar(n), not text;
--   * most string columns are nullable rather than NOT NULL DEFAULT ''.
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
    status         CHARACTER VARYING(20) NOT NULL DEFAULT 'PENDING',
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
    identity_type         CHARACTER VARYING(20) NOT NULL,
    provider              CHARACTER VARYING(50) NOT NULL DEFAULT '',
    provider_uid          TEXT,
    identifier_hash       CHARACTER VARYING(64) NOT NULL,
    identifier_ciphertext TEXT                  NOT NULL,
    identifier_masked     TEXT                  NOT NULL,
    key_version           CHARACTER VARYING(20) NOT NULL,
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
