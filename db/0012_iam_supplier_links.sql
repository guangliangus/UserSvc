-- =============================================================================
-- 0012 · iam.supplier_company_links: which approved suppliers hang off which company.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- Column order, types, constraint names and index names are byte-matched to what
--   dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
-- emits, so CI gate 04 diffs clean.
--
-- THE MOUNTING IS DATA SCOPE, not bookkeeping. The scope envelope in an access token hands every
-- member of a company the suppliers mounted onto it, and every member of a supplier the company it
-- hangs under; downstream services enforce data access from that claim. So an unmount is a
-- revocation, and the write path retires the affected accounts' tokens rather than waiting out the
-- expiry window.
--
-- SHAPE FOLLOWS THE LIVE GO TABLE (uam.supplier_company_links, 8 columns, read 2026-09-02) with one
-- deliberate difference: created_by / updated_by are NOT NULL DEFAULT '' here, where the Go table
-- leaves them nullable. The Go writer always stamps a value (falling back to 'system'), and this
-- service's convention maps a nullable text audit column onto a non-null .NET string - so the
-- default is the same value the code would have written anyway.
--
-- THERE ARE ROWS TO MIGRATE, and an earlier version of this header claimed there were none. Read
-- 2026-09-02, uam.supplier_company_links holds one ACTIVE mounting (ZZ90000008 -> LION) while
-- iam.supplier_company_links holds nothing. That row is not bookkeeping either: without it every
-- member of company LION resolves to no mounted suppliers here, and every member of supplier
-- ZZ90000008 resolves as independent - narrower than the truth, silently, with no warning line
-- anywhere to say so. The backfill at the end of this script copies it.
--
-- The column ORDER also differs from the Go table (which interleaves created_by after created_at):
-- it follows the model instead, because gate 04 diffs this file against the generated script and a
-- reordering would be reported as drift on every run forever.
--
-- NO FOREIGN KEYS, and that is the shape of the thing. supplier_code and company_code are logical
-- references into the product master data (pim.suppliers.code / pim.companies.code), which lives in
-- another service's database; the write path validates them over HTTP instead. A key here could
-- only ever point at a table that is not ours.
--
-- ON SEQUENCES: this script supplies no explicit ids, so supplier_company_links_id_seq is left
-- exactly where CREATE TABLE put it and the first mounting correctly takes id 1. (A seed that
-- supplies ids without a matching setval is how every later insert ends up colliding on the primary
-- key - see the note at the end of db/0007_iam_seed.sql.)
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS iam;

CREATE TABLE IF NOT EXISTS iam.supplier_company_links
(
    id            SERIAL      NOT NULL,
    supplier_code TEXT        NOT NULL,
    company_code  TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'ACTIVE'::text,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT        NOT NULL DEFAULT '',
    updated_by    TEXT        NOT NULL DEFAULT '',
    CONSTRAINT pk_supplier_company_links PRIMARY KEY (id),
    CONSTRAINT chk_supplier_links_status CHECK (status IN ('ACTIVE', 'UNLINKED'))
);

COMMENT ON TABLE  iam.supplier_company_links IS 'Supplier -> company mounting; UNLINKED rows are kept as history';
COMMENT ON COLUMN iam.supplier_company_links.supplier_code IS 'pim.suppliers.code (logical reference, no physical FK)';
COMMENT ON COLUMN iam.supplier_company_links.company_code IS 'pim.companies.code (logical reference, no physical FK)';
COMMENT ON COLUMN iam.supplier_company_links.status IS 'ACTIVE | UNLINKED (soft unlink; the row survives as history)';

-- At most one ACTIVE mounting per supplier. THIS partial unique index IS the invariant the read
-- path relies on, which is why the write path takes no row lock: a racing double mount is meant to
-- lose here rather than to be serialized behind a lock every read would pay for.
CREATE UNIQUE INDEX IF NOT EXISTS uk_supplier_links_active
    ON iam.supplier_company_links (supplier_code) WHERE status = 'ACTIVE';

-- The reverse read - which suppliers hang off this company - is crossed by every company context
-- resolution, so it is not optional.
CREATE INDEX IF NOT EXISTS idx_supplier_links_company
    ON iam.supplier_company_links (company_code);

-- -----------------------------------------------------------------------------
-- BACKFILL from the Go table, when it is reachable from this database.
--
-- Guarded on the uam schema existing, so this is a no-op in CI (a fresh container carries only
-- db/*.sql) and in any deployment where the Go service owns a separate database - there it becomes
-- a manual export, and the header above says what would otherwise be lost.
--
-- Two deliberate narrowings make it safe to run repeatedly, including at the cutover itself:
--   * ACTIVE rows only. UNLINKED rows are history, they carry no authority, and the Go table keeps
--     its own copy of them - copying them would only invite the second rule to mis-fire.
--   * a supplier this table has ALREADY heard of is skipped entirely. That is what stops a re-run
--     from resurrecting a mounting somebody unmounted here in the meantime, and what stops two
--     ACTIVE rows for one supplier from ever being attempted (uk_supplier_links_active would refuse
--     the second, taking the whole script down with it).
--
-- What it cannot do: close the dual-write window. While both services run, a mounting the Go side
-- changes after this has copied it has to be changed here too - by the endpoint, so that the audit
-- row and the token retirement happen with it. This backfill is the starting state, not a sync.
--
-- No setval: the ids are assigned by supplier_company_links_id_seq, not supplied here.
-- -----------------------------------------------------------------------------
-- Dynamic SQL, and it has to be: PostgreSQL analyses a whole statement before it runs, so a plain
-- INSERT naming uam.supplier_company_links would fail on a database without that schema even inside
-- a branch that is never taken. EXECUTE is what defers the name resolution to the guarded path.
DO $backfill$
BEGIN
    IF EXISTS (SELECT 1
               FROM information_schema.tables
               WHERE table_schema = 'uam' AND table_name = 'supplier_company_links') THEN
        EXECUTE $sql$
            INSERT INTO iam.supplier_company_links
                (supplier_code, company_code, status, created_at, updated_at, created_by, updated_by)
            SELECT go_link.supplier_code,
                   go_link.company_code,
                   'ACTIVE',
                   go_link.created_at,
                   go_link.updated_at,
                   -- The Go columns are nullable and this table's are not; 'system' is the same
                   -- fallback the Go writer uses when its context carries no user name.
                   COALESCE(NULLIF(go_link.created_by, ''), 'system'),
                   COALESCE(NULLIF(go_link.updated_by, ''), 'system')
            FROM uam.supplier_company_links AS go_link
            WHERE go_link.status = 'ACTIVE'
              AND NOT EXISTS (SELECT 1
                              FROM iam.supplier_company_links AS mounted
                              WHERE mounted.supplier_code = go_link.supplier_code)
        $sql$;
    END IF;
END
$backfill$;
