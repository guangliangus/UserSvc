-- =============================================================================
-- 0008 · feedback: the personal-centre feedback form's category catalogue and its submissions.
--
-- Run by hand (decision 14): DDL first, code second. Idempotent and re-runnable.
-- Column order, types, constraint names and index names are byte-matched to what
--   dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
-- emits, so CI gate 04 diffs clean.
--
-- TWO SHAPES FOLLOW THE LIVE DATABASE RATHER THAN THE TEAM'S OWN DDL PREFERENCES, because rows
-- already exist in both tables:
--   * feedback_types.code is a TEXT primary key, not a surrogate SERIAL. It is the value the client
--     submits and the value feedback.type_code references, so a surrogate would change the foreign
--     key and the wire contract at once and buy nothing.
--   * created_by / updated_by are nullable, not NOT NULL DEFAULT ''. The four seeded categories
--     carry no author, and inventing an empty string for them would be a value nobody wrote.
--
-- The table name is singular. "feedback" is a mass noun whose plural is itself, so "feedbacks"
-- would be worse English as well as a rename of a live table.
--
-- ON SEQUENCES AND setval: there is deliberately no setval in this script, and that is worth
-- stating because a seed that supplies explicit ids without one is how every later insert ends up
-- colliding on the primary key (see the note at the end of db/0007_iam_seed.sql). It does not
-- apply here: feedback_types is keyed by text and owns no sequence at all, and the seed below
-- inserts no rows into feedback, so feedback_id_seq is left exactly where CREATE TABLE put it and
-- the first submission correctly takes id 1.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS identity;

-- --------------------------------------------------------- feedback_types
CREATE TABLE IF NOT EXISTS identity.feedback_types
(
    code       TEXT        NOT NULL,
    labels     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    is_active  BOOLEAN     NOT NULL DEFAULT true,
    sort_order INTEGER     NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    updated_by TEXT,
    CONSTRAINT pk_feedback_types PRIMARY KEY (code)
);

COMMENT ON TABLE  identity.feedback_types IS
    'Selectable feedback categories for the personal-centre form. Managed by operations directly; there is no management API';
COMMENT ON COLUMN identity.feedback_types.code IS
    'Stable machine code submitted by the client; part of the published API contract';
COMMENT ON COLUMN identity.feedback_types.labels IS
    'Localized labels keyed by locale, e.g. {"en":"Bug report","ja":"..."}. Keys are case-sensitive';
COMMENT ON COLUMN identity.feedback_types.is_active IS
    'The soft delete. Only active categories are listed, and only an active one is accepted on submit';
COMMENT ON COLUMN identity.feedback_types.sort_order IS 'Ascending display order in the drop-down';

-- No index on is_active. The catalogue is four rows; a scan is cheaper than a lookup, and an index
-- on a near-constant boolean is one PostgreSQL would decline to use anyway.

-- --------------------------------------------------------------- feedback
CREATE TABLE IF NOT EXISTS identity.feedback
(
    id         SERIAL      NOT NULL,
    user_id    INTEGER     NOT NULL REFERENCES identity.users (id),
    type_code  TEXT        NOT NULL REFERENCES identity.feedback_types (code),
    content    TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    email      TEXT        NOT NULL,
    image_urls JSONB       NOT NULL DEFAULT '[]'::jsonb,
    status     TEXT        NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    updated_by TEXT,
    CONSTRAINT pk_feedback PRIMARY KEY (id),
    CONSTRAINT chk_feedback_status CHECK (status IN ('PENDING', 'REVIEWED', 'RESOLVED'))
);

COMMENT ON TABLE  identity.feedback IS
    'One submission of the personal-centre feedback form. Rows are never updated or deleted by this service';
COMMENT ON COLUMN identity.feedback.type_code IS 'Foreign key to feedback_types.code';
COMMENT ON COLUMN identity.feedback.content IS
    'The free text, trimmed, at most 500 Unicode code points (enforced in the application layer)';
COMMENT ON COLUMN identity.feedback.name IS
    'Contact name exactly as typed on the form; deliberately not taken from the profile';
COMMENT ON COLUMN identity.feedback.email IS 'Contact email exactly as typed on the form';
COMMENT ON COLUMN identity.feedback.image_urls IS
    'JSON array of uploaded image URLs, in the order they were attached. [] when there were none';
COMMENT ON COLUMN identity.feedback.status IS 'Triage status: PENDING | REVIEWED | RESOLVED';

-- Both foreign keys are indexed, plus status because the triage screen filters on it.
CREATE INDEX IF NOT EXISTS idx_feedback_user   ON identity.feedback (user_id);
CREATE INDEX IF NOT EXISTS idx_feedback_status ON identity.feedback (status);
CREATE INDEX IF NOT EXISTS idx_feedback_type   ON identity.feedback (type_code);

-- ------------------------------------------------- feedback_types · seed
-- CONTRACT data, read from the live database on 2026-09-02. These four codes are what the mobile
-- clients' drop-downs are wired to and what POST /api/v1/feedback validates against, so they are
-- part of the contract rather than sample data - a deployment without them has a feedback form
-- that accepts nothing.
--
-- The Chinese, Japanese, Korean, Thai and Vietnamese text below is data, not source. The
-- source-language guard only scans .cs files.
--
-- Re-runnable: ON CONFLICT (code) DO NOTHING. It will NOT repair a row that has drifted - that is
-- deliberate, because silently overwriting an operator's edit is worse than leaving it.
INSERT INTO identity.feedback_types (code, labels, is_active, sort_order) VALUES
  ('suggestion', '{"en": "Product suggestion", "ja": "製品へのご提案", "ko": "제품 제안", "th": "ข้อเสนอแนะผลิตภัณฑ์", "vi": "Góp ý sản phẩm", "zh-CN": "产品建议", "zh-TW": "產品建議"}'::jsonb, true, 1),
  ('bug',        '{"en": "Bug report", "ja": "不具合の報告", "ko": "오류 신고", "th": "รายงานข้อผิดพลาด", "vi": "Báo lỗi", "zh-CN": "功能异常", "zh-TW": "功能異常"}'::jsonb, true, 2),
  ('consult',    '{"en": "Usage question", "ja": "ご利用に関するお問い合わせ", "ko": "이용 문의", "th": "สอบถามการใช้งาน", "vi": "Tư vấn sử dụng", "zh-CN": "使用咨询", "zh-TW": "使用諮詢"}'::jsonb, true, 3),
  ('other',      '{"en": "Other", "ja": "その他", "ko": "기타", "th": "อื่นๆ", "vi": "Khác", "zh-CN": "其他", "zh-TW": "其他"}'::jsonb, true, 4)
ON CONFLICT (code) DO NOTHING;

-- ------------------------------------------------ user_sessions · comment
-- Deregistration adds a seventh revocation reason. The column is documented by a comment rather
-- than constrained by a CHECK, so this is the whole change - restated in full because COMMENT
-- replaces rather than appends. (It also picks up DEVICE_LIMIT, which RevocationReasons has had
-- since 0001 was written and the original comment omitted.)
COMMENT ON COLUMN identity.user_sessions.revoked_by IS
    'SELF | OTHER_DEVICE | SUPERSEDED | DEVICE_LIMIT | PASSWORD_CHANGE | ADMIN | TOKEN_REPLAY | DEREGISTERED';
