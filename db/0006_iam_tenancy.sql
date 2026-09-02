-- =============================================================================
-- 000X · iam schema: back-office tenant membership and its role bindings.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
--
-- MUST RUN AFTER the IAM catalogue script that creates iam.backend_users and iam.roles - the two
-- foreign keys below reference them. Renumber this file to the next free slot at merge time.
--
-- Why a schema of its own: back-office accounts and consumer accounts are different populations
-- with different lifecycles, so 'iam' is a bounded context beside 'identity' rather than a folder
-- inside it. There are deliberately NO foreign keys between the two schemas; a key across that
-- line would make the separation cosmetic and tie the two contexts' archival together.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS iam;

-- --------------------------------------------------------- tenant_members
CREATE TABLE IF NOT EXISTS iam.tenant_members
(
    id          SERIAL      NOT NULL,
    user_id     INTEGER     NOT NULL,
    tenant_type TEXT        NOT NULL,
    tenant_code TEXT        NOT NULL,
    is_admin    BOOLEAN     NOT NULL DEFAULT false,
    scope_all   BOOLEAN     NOT NULL DEFAULT false,
    dept_name   TEXT,
    status      TEXT        NOT NULL DEFAULT 'ACTIVE',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT,
    updated_by  TEXT,
    CONSTRAINT pk_tenant_members PRIMARY KEY (id),
    CONSTRAINT fk_tenant_members_user_id FOREIGN KEY (user_id)
        REFERENCES iam.backend_users (id) ON DELETE CASCADE,
    CONSTRAINT chk_tenant_members_type CHECK (tenant_type IN ('company', 'supplier')),
    CONSTRAINT chk_tenant_members_status CHECK (status IN ('ACTIVE', 'DISABLED', 'REMOVED'))
);

COMMENT ON TABLE  iam.tenant_members IS
    'Membership of one back-office account in one tenant. Rows are never deleted; status carries the lifecycle';
COMMENT ON COLUMN iam.tenant_members.tenant_code IS
    'pim.companies.code / pim.suppliers.code (logical reference, no physical FK); the sentinel ''*'' when scope_all';
COMMENT ON COLUMN iam.tenant_members.is_admin IS
    'Derived: true when at least one bound role is an admin role. Kept in step by the service, never authored';
COMMENT ON COLUMN iam.tenant_members.scope_all IS
    'Whole-dimension access (every company, or every supplier). The boolean is authoritative; tenant_code is a placeholder';
COMMENT ON COLUMN iam.tenant_members.status IS
    'ACTIVE | DISABLED | REMOVED (soft delete; re-adding the person revives this row)';

-- One row per person per tenant: what makes re-adding somebody revive their old row.
CREATE UNIQUE INDEX IF NOT EXISTS uk_tenant_members
    ON iam.tenant_members (user_id, tenant_type, tenant_code);

-- At most one whole-dimension row per person per dimension. Two would mean two role sets both
-- claiming to govern "every company".
CREATE UNIQUE INDEX IF NOT EXISTS uk_tenant_members_scope_all
    ON iam.tenant_members (user_id, tenant_type) WHERE scope_all;

-- The last-administrator guard runs on every membership write, so it gets its own partial index.
-- Note this is NOT unique: a tenant may have several administrators, and "at least one" is
-- enforced in the service, not by the schema.
CREATE INDEX IF NOT EXISTS idx_tenant_members_admin
    ON iam.tenant_members (tenant_type, tenant_code) WHERE is_admin = true AND status = 'ACTIVE';

CREATE INDEX IF NOT EXISTS idx_tenant_members_tenant
    ON iam.tenant_members (tenant_type, tenant_code, status);

CREATE INDEX IF NOT EXISTS idx_tenant_members_user
    ON iam.tenant_members (user_id, status);

-- ------------------------------------------------------ user_tenant_roles
CREATE TABLE IF NOT EXISTS iam.user_tenant_roles
(
    id         SERIAL      NOT NULL,
    member_id  INTEGER     NOT NULL,
    role_id    INTEGER     NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    CONSTRAINT pk_user_tenant_roles PRIMARY KEY (id),
    CONSTRAINT fk_user_tenant_roles_member_id FOREIGN KEY (member_id)
        REFERENCES iam.tenant_members (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_tenant_roles_role_id FOREIGN KEY (role_id)
        REFERENCES iam.roles (id) ON DELETE CASCADE
);

COMMENT ON TABLE  iam.user_tenant_roles IS
    'Role bindings of a tenant member, keyed by member_id and not by user_id: the same person holds different roles in different tenants';

CREATE UNIQUE INDEX IF NOT EXISTS uk_user_tenant_roles
    ON iam.user_tenant_roles (member_id, role_id);

-- The member side needs no index of its own: the unique index above leads with it.
CREATE INDEX IF NOT EXISTS idx_user_tenant_roles_role
    ON iam.user_tenant_roles (role_id);

-- No seed data. Memberships and their bindings are runtime data only.
