-- =============================================================================
-- 0009 · identity schema: WebAuthn/FIDO2 passkey credentials.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- =============================================================================

-- --------------------------------------------------------- user_passkeys
--
-- Two column types here are not this schema's usual TEXT, and both are deliberate:
--   * credential_id / public_key are BYTEA - raw binary that is never read as text. Base64 in a
--     TEXT column would cost a third more space and an encode on every comparison.
--   * transports is JSONB - a list of client hints whose members the browser defines.
--
-- attestation_type and name USED to be VARCHAR(20) / VARCHAR(100), justified as "kept as the live
-- database has it... widening a column another service still writes to is a change to a shared
-- table". That was false on both halves: this table is identity.user_passkeys, created by this
-- script and by nothing else; the Go service's passkey table is uam.user_passkeys, which held 0
-- rows when this was checked (2026-09-02) and which this service never reads or writes. There was
-- no shared table and no rows to be constrained by - identity.user_passkeys itself was empty.
-- Both columns are TEXT now, with the length checked in code (UserPasskey.MaxNameLength for the
-- label; attestation_type is a registry value the WebAuthn library hands us, never user input).
--
-- created_by / updated_by are nullable, unlike the rest of this schema's NOT NULL DEFAULT ''. That
-- one stands, and db/README.md records it: a credential is enrolled by its own holder through
-- WebAuthn, so there is no author string to write, and '' would be a value nobody wrote.
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
    attestation_type TEXT         NOT NULL DEFAULT 'none',
    backup_eligible  BOOLEAN      NOT NULL DEFAULT false,
    backup_state     BOOLEAN      NOT NULL DEFAULT false,
    name             TEXT,
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

-- ================================================ varchar(n) -> text, for databases created before
--
-- Same shape and the same reasoning as the block at the end of 0004, which measures what ALTER TYPE
-- does. Cheaper here: neither column is indexed and neither carries a CHECK, so only the DEFAULT on
-- attestation_type needs restating afterwards - it survives the conversion as
-- 'none'::character varying, which is not what a fresh database has.
DO $passkey_varchar_to_text$
DECLARE
    target RECORD;
BEGIN
    FOR target IN
        SELECT * FROM (VALUES ('attestation_type'), ('name')) AS t (column_name)
    LOOP
        IF EXISTS (SELECT 1
                     FROM information_schema.columns
                    WHERE table_schema = 'identity'
                      AND table_name = 'user_passkeys'
                      AND column_name = target.column_name
                      AND data_type = 'character varying') THEN
            EXECUTE format(
                'ALTER TABLE identity.user_passkeys ALTER COLUMN %I TYPE TEXT', target.column_name);
        END IF;
    END LOOP;
END
$passkey_varchar_to_text$;

ALTER TABLE identity.user_passkeys ALTER COLUMN attestation_type SET DEFAULT 'none';
