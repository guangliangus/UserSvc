-- =============================================================================
-- 00NN · identity.test_whitelist_users: the consumer accounts allowed to additionally see, and
--        order, the test company's tour products. Plus the back-office menu row for the page that
--        maintains it.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- MUST RUN AFTER db/0005_iam_rbac.sql and db/0007_iam_seed.sql: the menu insert at the end of this
-- script hangs the new node off the seeded 'system' root and matches on uk_menus_code.
--
-- WHY THIS TABLE EXISTS AT ALL - it is a departure from the Go service, recorded here rather than
-- only in a review comment. The Go original keeps this list in a single Redis set (uam:testwl) and
-- argues that losing the key merely empties the whitelist, which fails closed. That reasoning holds
-- for the read and not for the write: an operator who adds a tester and finds the list empty next
-- week cannot tell whether somebody removed them or the key was evicted. A table also carries the
-- two columns that answer the only questions ever asked of this list afterwards - who added an
-- entry, and when - and lets a removal be soft, so the record that an account was a tester between
-- two dates survives the removal.
--
-- WHY THE CONSUMER SCHEMA, when only a platform administrator ever writes it: every row is about a
-- consumer account, the hot read is a consumer authentication path (the is_test flag on token
-- validation), and the foreign key that keeps a back-office id out of this table is only
-- expressible inside one schema - no key crosses between identity and iam, by design. The two
-- realms are independent id sequences, so without that key a back-office account id could be
-- whitelisted and would inherit the consumer with the same id's membership.
--
-- ON SEQUENCES: no explicit ids are supplied here, so test_whitelist_users_id_seq stays where
-- CREATE TABLE put it and the menu row below takes its id from menus_id_seq, which
-- db/0007_iam_seed.sql has already setval'd past its own seeded ids.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.test_whitelist_users
(
    id         SERIAL      NOT NULL,
    user_id    INTEGER     NOT NULL,
    status     TEXT        NOT NULL DEFAULT 'ACTIVE'::text,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT        NOT NULL DEFAULT '',
    updated_by TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_test_whitelist_users PRIMARY KEY (id),
    CONSTRAINT chk_test_whitelist_users_status CHECK (status IN ('ACTIVE', 'REMOVED')),
    CONSTRAINT fk_test_whitelist_users_user_id FOREIGN KEY (user_id)
        REFERENCES identity.users (id) ON DELETE RESTRICT
);

COMMENT ON TABLE  identity.test_whitelist_users IS 'Consumer accounts allowed to see and order the test company products; the is_test verdict';
COMMENT ON COLUMN identity.test_whitelist_users.user_id IS 'identity.users.id - a consumer account, never a back-office one';
COMMENT ON COLUMN identity.test_whitelist_users.status IS 'ACTIVE | REMOVED (soft removal; the row survives as history)';

-- One ACTIVE entry per account. It is what makes re-adding somebody revive their old row rather
-- than insert a second one, and it is where "no duplicates" can be held against two administrators
-- clicking at once.
CREATE UNIQUE INDEX IF NOT EXISTS uk_test_whitelist_users_active
    ON identity.test_whitelist_users (user_id) WHERE status = 'ACTIVE';

-- The foreign key column indexed for the history read (every entry this account ever had, whatever
-- its status), which the partial index above cannot serve.
CREATE INDEX IF NOT EXISTS ix_test_whitelist_users_user_id
    ON identity.test_whitelist_users (user_id);

-- -----------------------------------------------------------------------------
-- The back-office menu row for the page that maintains the list.
--
-- WHY THIS IS ONLY A MENU ROW - no permission point, no role_permissions, no role_menus:
-- the audience is the platform super administrator alone, and the guard is
-- backend_users.is_super_admin read per request in the service layer, not a permission code. Three
-- consequences:
--   1. A permission point granted to exactly one boolean flag would be an indirection with no
--      payoff, so none is seeded.
--   2. No role_menus grant is needed: the tenant-context service gives a super administrator every
--      ACTIVE menu, so this node reaches them the moment it exists.
--   3. Nothing here has to appear in already-issued tokens, so - unlike a seeded permission code -
--      no signed-in administrator is locked out until they re-authenticate, and no token_version
--      bump is required after applying this.
--
-- audience is ["platform"] ONLY: the whitelist governs consumer-facing product visibility across
-- the platform, which is never a company- or supplier-tenant action. Note this is metadata and NOT
-- the thing that withholds the node - what actually keeps a tenant user from receiving this menu
-- code is the absence of any role_menus grant for it. Do not "fix" that by relying on audience;
-- grants are the gate.
--
-- icon MUST be a name the back-office UI's icon registry knows: an unknown name silently falls back
-- to a generic circle, with no error on either side. 'Shield' is registered.
--
-- sort_order 40: the 'system' group already uses 10 (exchange-rate-list), 20
-- (exchange-rate-config) and 30 (payment-config), so this appends rather than tying with a sibling.
--
-- ON CONFLICT names the columns rather than the constraint, because uk_menus_code is a unique INDEX
-- in this schema and not a table constraint - ON CONFLICT ON CONSTRAINT would not resolve it.
-- -----------------------------------------------------------------------------
INSERT INTO iam.menus (code, parent_id, name, path, icon, sort_order, audience, status, created_by, updated_by)
SELECT 'system-test-whitelist',
       parent.id,
       -- The seven locales are contract: the shell renders whichever the caller asked for and
       -- falls back to the code when a key is missing. Key order matches the seeded rows in
       -- db/0007_iam_seed.sql. Thai and Vietnamese are deliberately the English string - that is
       -- what the source system ships, and inventing a translation here would be worse.
       '{"en": "Test User Whitelist", "ja": "テストユーザー許可リスト", "ko": "테스트 사용자 화이트리스트", "th": "Test User Whitelist", "vi": "Test User Whitelist", "zh-CN": "测试用户白名单", "zh-TW": "測試用戶白名單"}'::jsonb,
       '/system/test-whitelist',
       'Shield',
       40,
       '["platform"]'::jsonb,
       'ACTIVE',
       'migration:0013',
       'migration:0013'
FROM iam.menus parent
WHERE parent.code = 'system' AND parent.parent_id IS NULL
ON CONFLICT (code) DO NOTHING;
