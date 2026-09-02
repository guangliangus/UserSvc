-- =============================================================================
-- 0006 · iam schema: the back-office role catalogue, permission points, menu registry
--        and the IAM audit trail.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
--
-- WHY A SEPARATE SCHEMA: back-office authorisation is a different bounded context from
-- consumer identity, so it gets its own namespace and its own grants. There are deliberately
-- NO foreign keys between 'iam' and 'identity' - a join across that line would make the
-- separation cosmetic. iam_audit_logs.actor_user_id is the visible consequence: it names a
-- back-office account and carries no FK, which is also what lets an audit row outlive the
-- account it names.
--
-- COLUMN NULLABILITY follows the live database rather than the house preference for
-- NOT NULL DEFAULT ''. menus.path, menus.icon and the created_by / updated_by columns really
-- are nullable there, and the seed inserts NULLs into them; tightening them here would refuse
-- the very rows this schema exists to hold.
--
-- CREATE ORDER is fixed by the foreign keys: menus, then permissions (permissions.menu_id
-- references it), then roles, then the two grant tables, then the audit trail. This script must
-- also run BEFORE the tenant-membership script, whose user_tenant_roles.role_id points at
-- iam.roles.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS iam;

-- ----------------------------------------------------------------- menus
CREATE TABLE IF NOT EXISTS iam.menus
(
    id         SERIAL      NOT NULL,
    code       TEXT        NOT NULL,
    parent_id  INTEGER,
    name       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    path       TEXT,
    icon       TEXT,
    sort_order INTEGER     NOT NULL DEFAULT 0,
    audience   JSONB       NOT NULL DEFAULT '["platform", "company", "supplier"]'::jsonb,
    status     TEXT        NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    updated_by TEXT,
    CONSTRAINT pk_menus PRIMARY KEY (id),
    CONSTRAINT menus_parent_id_fkey FOREIGN KEY (parent_id)
        REFERENCES iam.menus (id) ON DELETE RESTRICT,
    CONSTRAINT chk_menus_audience CHECK (jsonb_typeof(audience) = 'array'),
    CONSTRAINT chk_menus_status CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

COMMENT ON TABLE  iam.menus IS
    'Menu registry mirroring the back-office sidebar; the skeleton of the tenant permission tree';
COMMENT ON COLUMN iam.menus.code IS
    'Stable menu code = the front-end sidebar key (e.g. product-tour); immutable once live';
COMMENT ON COLUMN iam.menus.parent_id IS 'Parent menu; NULL = top-level group';
COMMENT ON COLUMN iam.menus.name IS
    'Localized names keyed by locale, e.g. {"zh-TW":"..."}; seven locales in the seeded rows';
COMMENT ON COLUMN iam.menus.path IS 'Route prefix (e.g. /product/tour); NULL for a pure group';
COMMENT ON COLUMN iam.menus.audience IS
    'JSONB string array of the tenant types that may see this menu: platform / company / supplier';
COMMENT ON COLUMN iam.menus.status IS 'ACTIVE | INACTIVE (INACTIVE is the soft delete)';

-- Named as in the source database. Nothing references these names, but keeping them means a dump
-- of this database and a dump of that one differ in nothing.
CREATE UNIQUE INDEX IF NOT EXISTS uk_menus_code  ON iam.menus (code);
CREATE INDEX        IF NOT EXISTS idx_menus_parent ON iam.menus (parent_id);

-- ----------------------------------------------------------- permissions
CREATE TABLE IF NOT EXISTS iam.permissions
(
    id          SERIAL      NOT NULL,
    code        TEXT        NOT NULL,
    name        TEXT        NOT NULL,
    description TEXT,
    module      TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'ACTIVE',
    created_at  TIMESTAMPTZ          DEFAULT now(),
    updated_at  TIMESTAMPTZ          DEFAULT now(),
    menu_id     INTEGER,
    CONSTRAINT pk_permissions PRIMARY KEY (id),
    CONSTRAINT permissions_menu_id_fkey FOREIGN KEY (menu_id)
        REFERENCES iam.menus (id) ON DELETE RESTRICT,
    CONSTRAINT permissions_status_check CHECK (status IN ('ACTIVE', 'INACTIVE'))
);

COMMENT ON TABLE  iam.permissions IS 'Permission points, the unit the request pipeline checks';
COMMENT ON COLUMN iam.permissions.menu_id IS
    'Owning menu; NULL = a service-level point, absent from the tenant permission tree';
COMMENT ON COLUMN iam.permissions.status IS 'ACTIVE | INACTIVE (INACTIVE grants nothing anywhere)';

-- ON DELETE RESTRICT above is why deleting a menu has to delete its permission points first, in
-- the same transaction. That order is not interchangeable.
CREATE UNIQUE INDEX IF NOT EXISTS permissions_code_key ON iam.permissions (code);
CREATE INDEX        IF NOT EXISTS idx_permissions_menu ON iam.permissions (menu_id);

-- ----------------------------------------------------------------- roles
CREATE TABLE IF NOT EXISTS iam.roles
(
    id             SERIAL      NOT NULL,
    code           TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    description    TEXT,
    category       TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ          DEFAULT now(),
    updated_at     TIMESTAMPTZ          DEFAULT now(),
    created_by     TEXT,
    updated_by     TEXT,
    owner_type     TEXT        NOT NULL DEFAULT 'SYSTEM',
    owner_code     TEXT,
    is_admin       BOOLEAN     NOT NULL DEFAULT false,
    parent_role_id INTEGER,
    CONSTRAINT pk_roles PRIMARY KEY (id),
    CONSTRAINT roles_parent_role_id_fkey FOREIGN KEY (parent_role_id)
        REFERENCES iam.roles (id) ON DELETE RESTRICT,
    CONSTRAINT chk_roles_owner_type CHECK (owner_type IN ('SYSTEM', 'COMPANY', 'SUPPLIER')),
    CONSTRAINT chk_roles_category   CHECK (category IN ('', 'platform', 'supplier', 'company')),
    -- An administrator role is by construction a platform role: its holders inherit the widest
    -- delegation ceiling, so a tenant must not be able to mint one.
    CONSTRAINT chk_roles_admin_system CHECK (NOT is_admin OR owner_type = 'SYSTEM'),
    -- Self-loop guard only; deeper cycles are refused by the service, which walks the ancestor
    -- chain. SQL cannot express that here.
    CONSTRAINT chk_roles_parent_not_self CHECK (parent_role_id IS DISTINCT FROM id),
    -- A tenant's own role is pinned to its own dimension. A platform role picks freely, which is
    -- how the platform writes a template FOR suppliers.
    CONSTRAINT chk_roles_category_owner CHECK (
        owner_type = 'SYSTEM'
        OR category = ''
        OR (owner_type = 'COMPANY'  AND category = 'company')
        OR (owner_type = 'SUPPLIER' AND category = 'supplier')
    )
);

COMMENT ON TABLE  iam.roles IS 'Role catalogue: named bundles of menu and permission grants';
COMMENT ON COLUMN iam.roles.owner_type IS
    'SYSTEM = platform built-in; COMPANY / SUPPLIER = a tenant custom role';
COMMENT ON COLUMN iam.roles.owner_code IS 'Owning tenant code; NULL for a SYSTEM role (no owner)';
COMMENT ON COLUMN iam.roles.is_admin IS
    'Administrator role (role-group leader); settable only by the platform super administrator';
COMMENT ON COLUMN iam.roles.parent_role_id IS
    'Leader of the owning role group; NULL = top level. The parent must have is_admin = true';
COMMENT ON COLUMN iam.roles.category IS
    'platform | supplier | company; empty = uncategorised legacy row, bindable nowhere. Immutable';

-- The uniqueness of a role code is scoped to its owner, and COALESCE folds the NULL owner code of
-- every platform role into one comparable value - without it two platform roles could share a code,
-- since NULL is never equal to NULL. It is an EXPRESSION index, which EF Core cannot model, so it
-- lives only here; the service refuses a duplicate code globally, which is stricter still.
CREATE UNIQUE INDEX IF NOT EXISTS uk_roles_owner_code
    ON iam.roles (owner_type, COALESCE(owner_code, ''), code);

CREATE INDEX IF NOT EXISTS idx_roles_parent ON iam.roles (parent_role_id);
CREATE INDEX IF NOT EXISTS idx_roles_owner  ON iam.roles (owner_type, owner_code)
    WHERE owner_type <> 'SYSTEM';

-- ------------------------------------------------------- role_permissions
CREATE TABLE IF NOT EXISTS iam.role_permissions
(
    id            SERIAL      NOT NULL,
    role_id       INTEGER     NOT NULL,
    permission_id INTEGER     NOT NULL,
    created_at    TIMESTAMPTZ          DEFAULT now(),
    created_by    TEXT,
    CONSTRAINT pk_role_permissions PRIMARY KEY (id),
    CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES iam.roles (id) ON DELETE CASCADE,
    CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id)
        REFERENCES iam.permissions (id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.role_permissions IS
    'Permission grants of a role. Replaced wholesale, never edited in place';

-- The constraint name is part of the contract: seed scripts target it by name in
-- ON CONFLICT ON CONSTRAINT.
CREATE UNIQUE INDEX IF NOT EXISTS role_permissions_role_id_permission_id_key
    ON iam.role_permissions (role_id, permission_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id
    ON iam.role_permissions (role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id
    ON iam.role_permissions (permission_id);

-- ------------------------------------------------------------ role_menus
CREATE TABLE IF NOT EXISTS iam.role_menus
(
    id         SERIAL      NOT NULL,
    role_id    INTEGER     NOT NULL,
    menu_id    INTEGER     NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    CONSTRAINT pk_role_menus PRIMARY KEY (id),
    CONSTRAINT role_menus_role_id_fkey FOREIGN KEY (role_id)
        REFERENCES iam.roles (id) ON DELETE CASCADE,
    CONSTRAINT role_menus_menu_id_fkey FOREIGN KEY (menu_id)
        REFERENCES iam.menus (id) ON DELETE CASCADE
);

COMMENT ON TABLE iam.role_menus IS
    'Menu grants of a role. Two invariants are enforced by the service, not here: a granted '
    'permission point''s owning menu must be granted, and a granted child implies its parent';

CREATE UNIQUE INDEX IF NOT EXISTS uk_role_menus ON iam.role_menus (role_id, menu_id);
CREATE INDEX        IF NOT EXISTS idx_role_menus_menu ON iam.role_menus (menu_id);

-- ------------------------------------------------------- iam_audit_logs
CREATE TABLE IF NOT EXISTS iam.iam_audit_logs
(
    id            SERIAL      NOT NULL,
    actor_user_id INTEGER     NOT NULL,
    actor_name    TEXT,
    tenant_type   TEXT,
    tenant_code   TEXT,
    action        TEXT        NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    before_data   JSONB,
    after_data    JSONB,
    ip            TEXT,
    request_id    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_iam_audit_logs PRIMARY KEY (id)
);

COMMENT ON TABLE iam.iam_audit_logs IS
    'Append-only trail of IAM administrative actions. No update path and no delete path exists in '
    'the service; the repository port exposes nothing but an append';
COMMENT ON COLUMN iam.iam_audit_logs.actor_user_id IS
    'The back-office account that acted. Deliberately not a foreign key: it lives in another '
    'bounded context, and an audit row must outlive the account it names';
COMMENT ON COLUMN iam.iam_audit_logs.target_id IS
    'Text, not an integer: today a role id, tomorrow possibly a tenant code';

-- Both descend on created_at: every read here wants the newest entries for one actor or one
-- tenant, and a descending index makes that ordering free rather than a sort over all history.
CREATE INDEX IF NOT EXISTS idx_iam_audit_actor
    ON iam.iam_audit_logs (actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iam_audit_tenant
    ON iam.iam_audit_logs (tenant_type, tenant_code, created_at DESC);
