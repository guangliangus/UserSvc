-- =============================================================================
-- 0003 · verification codes: the proof-of-ownership trail behind every code sent.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- Index names and column order are byte-matched to what
--   dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
-- emits, so CI gate 04 diffs clean. In particular, the ticket-lookup index name is TRUNCATED at
-- PostgreSQL's 63-character identifier limit and EF emits the same truncation - do not "fix" it.
--
-- There is deliberately NO updated_at column: nothing reads one, and the row's whole lifecycle is
-- already carried by verified_at and consumed_at. Nothing is ever deleted here, and no column
-- needs the status + partial-unique-index treatment because nothing on this table is unique.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.verification_codes
(
    id                             SERIAL      NOT NULL,
    target_hash                    TEXT        NOT NULL,
    device_id_hash                 TEXT        NOT NULL DEFAULT '',
    purpose                        TEXT        NOT NULL,
    code_hash                      TEXT        NOT NULL,
    expires_at                     TIMESTAMPTZ NOT NULL,
    verified_at                    TIMESTAMPTZ,
    verification_ticket_hash       TEXT        NOT NULL DEFAULT '',
    verification_ticket_expires_at TIMESTAMPTZ,
    consumed_at                    TIMESTAMPTZ,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by                     TEXT        NOT NULL DEFAULT '',
    updated_by                     TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_verification_codes PRIMARY KEY (id)
);

COMMENT ON TABLE  identity.verification_codes IS
    'One issued verification code, and the ticket minted from it once verified. Rows are never deleted';
COMMENT ON COLUMN identity.verification_codes.target_hash IS
    'Blind index: HMAC-SHA256 of the trimmed, lowercased phone or email';
COMMENT ON COLUMN identity.verification_codes.device_id_hash IS
    'Blind index of the X-Device-ID header; empty when the request carried none';
COMMENT ON COLUMN identity.verification_codes.purpose IS
    'auth | backoffice_auth | reset_password | backoffice_reset_password | bind';
COMMENT ON COLUMN identity.verification_codes.code_hash IS
    'Blind index of the digits that were sent; the plaintext exists only in transit';
COMMENT ON COLUMN identity.verification_codes.verified_at IS
    'When the code was exchanged for a ticket; NULL until then';
COMMENT ON COLUMN identity.verification_codes.verification_ticket_hash IS
    'Blind index of the ticket handed to the client; empty before one is minted';
COMMENT ON COLUMN identity.verification_codes.verification_ticket_expires_at IS
    'The ticket deadline, independent of expires_at';
COMMENT ON COLUMN identity.verification_codes.consumed_at IS
    'When the row was retired, by ticket consumption or by a newer code superseding it';

-- Verify hot path: newest live row for this target, purpose and code. created_at descends inside
-- the index so the ORDER BY is free rather than a sort over every code ever sent to that address.
CREATE INDEX IF NOT EXISTS ix_verification_codes_target_hash_purpose_code_hash_created_at
    ON identity.verification_codes (target_hash, purpose, code_hash, created_at DESC)
    WHERE consumed_at IS NULL;

-- Consume hot path. Its leading (target_hash, purpose) columns also serve the send path's
-- retire-the-previous-live-code UPDATE, so that statement needs no index of its own.
-- The name is truncated to 63 characters by PostgreSQL, and EF emits it truncated too.
CREATE INDEX IF NOT EXISTS ix_verification_codes_target_hash_purpose_verification_ticket_
    ON identity.verification_codes (target_hash, purpose, verification_ticket_hash)
    WHERE consumed_at IS NULL;

-- The two risk-control fallback counts. Unfiltered on purpose: they count history, including the
-- consumed rows the indexes above deliberately exclude.
CREATE INDEX IF NOT EXISTS ix_verification_codes_target_hash_created_at
    ON identity.verification_codes (target_hash, created_at);
CREATE INDEX IF NOT EXISTS ix_verification_codes_device_id_hash_created_at
    ON identity.verification_codes (device_id_hash, created_at);
