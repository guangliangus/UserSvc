# 数据库脚本

**应用永不改库**（决策 14）。DDL 以顺序编号的幂等脚本手动执行：先执行 DDL，再发布代码。

## 为什么不用 EF Migration

滚动更新期间新旧两个版本的代码同时在跑，DDL 必须**向后兼容且早于代码发布**。
让应用启动时改库，等于把 schema 变更交给一个可能被并发执行、可能中途失败、可能回滚的过程。

## 执行

```bash
psql "$DATABASE_URL" -f db/0001_identity.sql
```

脚本必须**反复执行结果一致**（`CREATE ... IF NOT EXISTS`）。CI 会连跑两次做验证。

## 改了实体之后

```bash
dotnet dotnet-ef dbcontext script \
  -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
```

它按当前模型输出**全量建库 SQL**（只输出文本，不执行）。把它和 `db/` 里的脚本对照，
摘出增量整理成新编号脚本，评审后交付执行。CI 里这一步是门禁，防止模型与库悄悄漂移。

## 手工核对门禁 04 的方法

两边各建一个库再对比投影，比读两份 SQL 可靠：

```bash
createdb gate04_ddl && for f in db/*.sql; do psql -v ON_ERROR_STOP=1 -d gate04_ddl -f "$f"; done
createdb gate04_model && psql -v ON_ERROR_STOP=1 -d gate04_model -f model.sql
```

然后对比三份投影：列（`information_schema.columns`：名字 / 类型 / 可空 / 默认值）、
约束（`pg_constraint` + `pg_get_constraintdef`）、索引（`pg_indexes`）。
2026-09-03 实测（`db/0014` 的 `identity.task_queues` 已在内）：288 列、244 约束（这个数把 PostgreSQL 18 记进 `pg_constraint` 的 `NOT NULL` 也算上了）、DDL 85 个索引 / 模型 84 个。门禁 04 自己报的是同一批对象的另一种投影：db/ 侧 410 个、模型侧 409 个。

## 门禁 04 的已知例外

对照检查会报出下面这些差异。它们是**有意的**，不要"修"：

| 对象 | 为什么两边不同 |
|---|---|
| `iam.uk_roles_owner_code` | `UNIQUE (owner_type, COALESCE(owner_code, ''), code)` —— 表达式索引，EF Core 无法建模。活库里就是这个形状：`owner_code` 可空，而 `NULL <> NULL`，不加 `COALESCE` 就拦不住同一个 SYSTEM 角色码重复。服务层另有一道全局唯一性检查，比它更严 |
| **列默认值（一整类，61 处）** | 见下节。**默认值的比对是单向的** |
| `iam.*` 与 `identity.user_passkeys` / `identity.feedback*` 的可空字符串列 | 见下节。两边**一致**，只是不符合"尽量 NOT NULL"，写在这里免得每次评审重新发现 |
| `identity.feedback_types.code` 是 TEXT 主键 | 不符合"自增主键，不用业务字段做主键"。两边一致。它是客户端提交的值、也是 `feedback.type_code` 的外键目标，换成代理键要同时改外键和已发布的 wire 契约，什么也换不来。这个理由跟表里有没有行无关 |

新增例外时把它加进这张表，并写清"为什么两边不同"，而不是"为什么懒得改"。

### 例外一：列默认值，比对是单向的

`db/*.sql` 里有 61 个列默认值（`now()` · `''::text` · `'ACTIVE'::text` · `0` · `false` ·
`'{}'::jsonb`）在 EF 模型里没有对应声明（2026-09-03 实测；类型和可空性零差异。原本是 52 个，
`db/0014` 的 `identity.task_queues` 又加了 9 个——那张表的默认值**全部只写在 DDL 里**，
正是下面这张表里安全的那个方向）。这**不是漂移**：

- 列默认值是**数据库**给"不是 EF 的写入者"兜底的——手写脚本、psql、运维改数据。它属于 DDL。
- EF 只在一种情况下需要知道它：**它要故意不把这列写进 INSERT**。EF 判断"要不要写"的办法是拿
  当前值跟 sentinel（值类型的 CLR 默认值）比，所以一旦模型里声明了存储默认值，
  **等于 CLR 默认值的那个值就永远写不进去**。
- 所以方向决定性质：

| 方向 | 结论 |
|---|---|
| DDL 有、模型没有 | **正常**，就是上面这 52 处。EF 每次都显式写值，数据库的默认值只对别的写入者生效 |
| 模型有、DDL 没有 | **缺陷，必须修**。EF 会漏掉这一列，指望一个根本不存在的默认值来填 —— 落地是 NULL 或 23502 |

反向那种真的发生过一次：`iam.backend_identities.provider_details` 在模型里声明了
`'{}'::jsonb`，注释还写着"活库自己的默认值"，而活库这一列**没有默认值**，三行数据全是 NULL。
已经从模型里删掉。

同一个机制还是那两条每次启动都打的 EF 警告（`FeedbackType.IsActive`、`Role.IsAdmin`：
"configured with a database-generated default, but has no configured sentinel value"）的根因。
`is_active` 那条不只是噪音：存储默认值是 `true` 而 bool 的 sentinel 是 `false`，
所以 `IsActive = false` 的实体**根本不会把这列写进 INSERT**，插出来的行是 ACTIVE ——
"停用的分类"当时插不进去。官方给的解法 `HasSentinel(null)` 在这里用不了，EF 10 直接拒绝
（`The sentinel value 'null' is not assignable to the property ... of type 'bool'`，
连 DbContext 都构造不出来）。改法是**模型不再声明**这两个默认值，列上的 `DEFAULT` 留在 DDL 里。

### 例外二：可空的字符串列

`iam.backend_users` / `iam.backend_identities` / `identity.user_passkeys` /
`identity.feedback*` 的多数字符串列是可空的，而 `identity.users` 那批用的是 `NOT NULL DEFAULT ''`。
两边（DDL 与模型）一致，逐列的理由：

| 列 | 为什么保持可空 |
|---|---|
| `backend_users.password_hash` | NULL 是有含义的：**这个账号没有密码这道门**（只走过企业目录/OTP 登录），跟"空密码"不是一回事 |
| `backend_users.first_name` · `last_name` · `nickname` · `avatar` · `staff_code` · `dept_no` · `dept_name` | 活库里就是 NULL（2026-09-02：11 行中 avatar 全空、staff_code / dept_no 4 行为空），而领域属性是 `string?`。改成 NOT NULL 要同时做数据迁移和领域类型变更，买到的只是对称 |
| `backend_identities.provider_uid` · `provider_details` | 密码/OTP 建的身份**没有上游载荷**，NULL 就是"没有"，`''` / `'{}'` 是编出来的值 |
| `user_passkeys.name` · `feedback*.created_by` · `updated_by` | 凭据由持有者自己注册、分类由运维直接改库，没有"作者"可写 |

**新表不要跟着抄这个形状**：新表按约定用 `NOT NULL DEFAULT ''`，除非 NULL 像
`password_hash` 那样确实带信息。

> 已经被删掉的一条错误理由，记在这里免得被重新发明：`0004` / `0009` 曾用
> "existing rows are the constraint" 为 7 个 `varchar(n)` 列辩护。这个前提是假的 ——
> `iam` 是本服务自己的 schema，里面每一行都是本服务写的（2026-09-02：11 个账号、3 个身份，
> `created_by` 全是 `probe` / `system`），Go 服务的行在 `uam`，两个平面之间没有任何连接；
> `identity.user_passkeys` 当时是空表。同样这五个概念，`0001` 建 `identity.user_identities`
> 时用的就是 `text`。七列现已全部改为 `text`，`CHECK` 一条没动。

## 变更纪律

- 只做向后兼容的变更：加列给默认值
- 改名走四步：新增 → 双写 → 迁移 → 删除
- 不物理删除数据：用 `status` 软状态 + partial unique index
- **外键名以 DDL 为准，模型里用 `HasConstraintName` 跟上。** EF 自己会起
  `fk_user_identities_users_user_id`，PostgreSQL 的内联 `REFERENCES` 起的是
  `user_identities_user_id_fkey` —— 两边都应用过的库会带着**同一个外键的两份**，
  每次插入验两遍，而 schema 对比永远清不干净
- **`ON DELETE` 写出来，别靠默认。** 省掉就是 `NO ACTION`，而模型里 EF 写的是 `RESTRICT`；
  两者只在 `DEFERRABLE` 约束上才有区别（本库一个都没有），所以它不是行为差异，
  是**两边读起来不一样**的差异，而门禁只能看见文本
- **改字符串列的类型要连默认值和 CHECK 一起改。** 实测（PostgreSQL 18.1）：
  `varchar(n) → text` 是 binary coercible，**不重写表**（relfilenode 不变），但
  ① 谓词里提到该列的索引会被重建（`identity_type` 上那 6 个 partial unique index），
  ② 列默认值**保留旧类型**（`'PENDING'::character varying`），
  ③ `CHECK` 会被改写成 `ARRAY[('email'::character varying)::text, ...]`。
  ②③ 跟新建库的文本不一样，所以脚本里要跟着 `SET DEFAULT` 和 drop/re-add `CHECK`
  —— 见 `0004` 末尾那一段
