-- =============================================================================
-- 0008 · identity schema: WebAuthn/FIDO2 passkey credentials.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- =============================================================================

-- --------------------------------------------------------- user_passkeys
--
-- Column types here are the live table's, not this schema's usual defaults, and the differences
-- are deliberate:
--   * credential_id / public_key are BYTEA - raw binary that is never read as text. Base64 in a
--     TEXT column would cost a third more space and an encode on every comparison.
--   * transports is JSONB - a list of client hints whose members the browser defines.
--   * attestation_type is VARCHAR(20), the one length-constrained string column in this schema.
--     Kept as the live database has it: the longest registered attestation format identifier is
--     'android-safetynet' at 17 characters, and widening a column another service still writes to
--     is a change to a shared table rather than a tidy-up.
--   * created_by / updated_by are nullable, matching the live table, where the rest of this schema
--     uses NOT NULL DEFAULT ''.
--
-- Rows here are deleted for real when a user removes a key, which is the one documented exception
-- to the "retire, never delete" rule: a retired row would keep occupying the unique index on
-- credential_id and stop the user ever re-enrolling the same authenticator.
CREATE TABLE IF NOT EXISTS identity.user_passkeys
(
    id               SERIAL       NOT NULL,
    user_id          INTEGER      NOT NULL,
    credential_id    BYTEA        NOT NULL,
    public_key       BYTEA        NOT NULL,
    sign_count       BIGINT       NOT NULL DEFAULT 0,
    aaguid           BYTEA,
    transports       JSONB        NOT NULL DEFAULT '[]'::jsonb,
    attestation_type VARCHAR(20)  NOT NULL DEFAULT 'none',
    backup_eligible  BOOLEAN      NOT NULL DEFAULT false,
    backup_state     BOOLEAN      NOT NULL DEFAULT false,
    name             VARCHAR(100),
    last_used_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by       TEXT,
    updated_by       TEXT,
    CONSTRAINT pk_user_passkeys PRIMARY KEY (id),
    CONSTRAINT user_passkeys_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES identity.users (id) ON DELETE RESTRICT
);

COMMENT ON TABLE  identity.user_passkeys IS
    'WebAuthn/FIDO2 passkey credentials; one account may hold several';
COMMENT ON COLUMN identity.user_passkeys.credential_id IS
    'WebAuthn credential id; a discoverable login is located by this alone';
COMMENT ON COLUMN identity.user_passkeys.public_key IS 'COSE-encoded public key';
COMMENT ON COLUMN identity.user_passkeys.sign_count IS
    'Authenticator signature counter. A value that does not advance means the credential was cloned';
COMMENT ON COLUMN identity.user_passkeys.aaguid IS
    'Authenticator model identifier, 16 raw bytes; NULL when the authenticator did not disclose one';
COMMENT ON COLUMN identity.user_passkeys.transports IS
    'Client-reported transports, e.g. ["internal","hybrid"]';
COMMENT ON COLUMN identity.user_passkeys.attestation_type IS
    'Attestation statement format: none | packed | tpm | apple | android-key | android-safetynet | fido-u2f';
COMMENT ON COLUMN identity.user_passkeys.backup_eligible IS 'BE flag; fixed for the credential''s lifetime';
COMMENT ON COLUMN identity.user_passkeys.backup_state IS 'BS flag; rewritten on every accepted assertion';
COMMENT ON COLUMN identity.user_passkeys.name IS 'User-visible label, e.g. "iPhone Face ID"';

-- Unique service-wide, not per account: a discoverable login turns this value into an account
-- before anyone has said who they are, so two accounts claiming one credential id would make that
-- lookup ambiguous at exactly the wrong moment.
CREATE UNIQUE INDEX IF NOT EXISTS ix_user_passkeys_credential_id
    ON identity.user_passkeys (credential_id);
-- Listing an account's credentials, and building the allow-list for an identifier-scoped login.
CREATE INDEX IF NOT EXISTS ix_user_passkeys_user_id
    ON identity.user_passkeys (user_id);

-- This script inserts no rows, so there is no sequence to advance. Were seed rows ever added here
-- with explicit ids, they would have to be followed by the setval form used in 0007 - PostgreSQL
-- does not advance a SERIAL for a value it did not generate, and the next insert would collide.
