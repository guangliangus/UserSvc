-- =============================================================================
-- 000N · third-party login identities: WeChat, WeChat Mini Program, Firebase, LINE.
-- (numbered 0008 when I verified it; the orchestrator owns the final number and placement)
--
-- Run by hand (decision 14). Idempotent and re-runnable: it only adds columns and indexes to
-- identity.user_identities, which 0001 created. No explicit ids are supplied anywhere, so there is
-- no sequence to advance with setval.
--
-- WHY THREE COLUMNS AND NOT NONE
-- The provider subject cannot live in identifier_hash alone. That column holds a blind index of
-- the identifier, and two lookups this slice depends on cannot be expressed over a hash:
--   * WeChat's union id is the same value across every application of one Open Platform account,
--     and it is the ONLY way to recognise that a mini-program openid and a web openid belong to
--     one human. It has to be readable and equality-searchable, so it is a column.
--   * A Firebase uid is not stable: Firebase mints a new one whenever its user record is deleted
--     and re-created for the same Google or Apple account. The third-party account's own subject
--     never moves, so uniqueness is keyed on (provider, provider_uid) while lookups hash the uid -
--     and the sign-in path falls back to the column when the hash goes stale.
-- Neither value is a credential, which is why storing them in the clear is not a decision 13
-- violation: they identify an account at a provider, they do not authenticate anyone.
-- =============================================================================

ALTER TABLE identity.user_identities
    ADD COLUMN IF NOT EXISTS provider         TEXT  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_uid     TEXT  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS provider_details JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN identity.user_identities.provider IS
    'Application or sign-in provider inside the identity type: '''' (web WeChat, LINE) | miniprogram | google.com | apple.com | facebook.com';
COMMENT ON COLUMN identity.user_identities.provider_uid IS
    'The provider''s own durable subject: WeChat union id, or the third-party sub behind a Firebase uid. Empty for phone, email and passkey';
COMMENT ON COLUMN identity.user_identities.provider_details IS
    'Provider-supplied decoration only, never a lookup key: union_id | email_masked | name';

-- One active identity per (type, provider, subject). Filtered to rows that actually carry a
-- subject, or every phone and email identity would collide on ('', '').
CREATE UNIQUE INDEX IF NOT EXISTS ix_user_identities_identity_type_provider_provider_uid
    ON identity.user_identities (identity_type, provider, provider_uid)
    WHERE status = 'ACTIVE' AND provider_uid <> '';

-- The WeChat unification lookup: given a union id, find the earliest active WeChat-family
-- identity. Deliberately NOT unique - one human legitimately holds one row per WeChat application.
CREATE INDEX IF NOT EXISTS ix_user_identities_provider_uid
    ON identity.user_identities (provider_uid)
    WHERE provider_uid <> '';
