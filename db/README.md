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

## 门禁 04 的已知例外

对照检查会报出下面这些差异。它们是**有意的**，不要"修"：

| 对象 | 为什么模型里没有 |
|---|---|
| `iam.uk_roles_owner_code` | `UNIQUE (owner_type, COALESCE(owner_code, ''), code)` —— 表达式索引，EF Core 无法建模。活库里就是这个形状：`owner_code` 可空，而 `NULL <> NULL`，不加 `COALESCE` 就拦不住同一个 SYSTEM 角色码重复。服务层另有一道全局唯一性检查，比它更严 |

新增例外时把它加进这张表，并写清"为什么模型表达不了"，而不是"为什么懒得改"。

## 变更纪律

- 只做向后兼容的变更：加列给默认值
- 改名走四步：新增 → 双写 → 迁移 → 删除
- 不物理删除数据：用 `status` 软状态 + partial unique index
