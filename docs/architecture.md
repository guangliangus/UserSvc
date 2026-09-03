# 架构约束

完整设计与每条决策的理由见**架构蓝图**：
<https://claude.ai/code/artifact/f2d16240-1947-48aa-b58d-46c24258d4a0>

本文只列**代码里被强制执行**的部分。改动这些约束前，先改蓝图。

**有意留着不做的事**不在这里，在 [`known-open.md`](known-open.md)——每条写清开着的是什么、
代价是什么、关掉它需要什么。

## 先读这一节：两个身份平面，两套独立编号

`identity.users`（C 端用户）与 `iam.backend_users`（后台运营）是**两个限界上下文**，
各自独立编号。所以后台运营 5 号与 C 端用户 5 号是两个人、同一个整数。

`iam.*` 与 `identity.*` 之间**故意没有外键**：同一个邮箱可以既是客户又是员工，那是两个账号，
合成一个意味着停用一名员工会顺带停用他的个人订单账号。没有外键，也就没有任何东西能"顺手"
把两个平面 join 回去。

代价是**每一个只拿到一个 `int` 的地方都少了一半信息**。这一半已经咬过两次，症状完全不同：

**第一次 · 会话表串号。** `identity.user_sessions.user_id` 存的就是这个裸整数，于是
「这个用户的活跃会话」变成一次跨平面查询：运营的会话出现在 C 端用户的设备列表里；C 端的
设备数上限淘汰会撤销运营的会话；而 `(user_id, device_id)` 上的 partial unique index 让两人中
后登录的那个**根本登不进来**——同一个 device_id，同一个整数，一个把另一个锁在门外。

**第二次 · C 端端点能被后台令牌打开。** 两个平面由**同一个 OpenIddict 实例**颁发令牌，
所以运营的 access token 在 C 端路由上是一个完全合法的 bearer token，足以满足一个裸
`[Authorize]`；而它的 `sub` 是一个 `iam.backend_users` id，那些端点接着拿它去查
`identity.users`。wave 7 实测（跑起来才发现的，不是读出来的）：`sub=1` 的后台令牌 200 读到
C 端用户 1 的完整 `GET /api/v1/user/profile`；`DELETE /api/v1/account` 带同一个令牌进到了
`DeregisterAsync`——会关掉那个 C 端账号并踢掉他所有设备。请求本身没有任何畸形。

两条强制做法，一条对一次：

| 层 | 做法 |
|---|---|
| 会话表 | `identity.user_sessions.realm`（`CONSUMER` \| `BACKOFFICE`），聚合与仓储只收 `SessionSubject`，没有默认值也没有回落。`SessionSubject` 没有公开构造函数，所以调用点**没法忘记** realm——这是它和"带默认值的参数"的全部区别 |
| 路由 | **`/api/v{n}/back-office/**` 是 B 端，其余是 C 端**，前缀即平面。`PlaneSeparationTests` 让"目录在 BackOffice 下但路由不在该前缀"、"路由在该前缀但类不在该目录"两种情况都构建失败。曾经跨在 `/api/v{n}/auth/` 下的五个后台端点已迁走 |
| 授权 | B 端 controller 必须带 `BackOfficePolicies.BackOffice` 或 `TenantSelection`（或整类 `[AllowAnonymous]`，登录门）。**裸 `[Authorize]` 不算**——两个平面同一个 OpenIddict 实例，消费者令牌照样满足它。`RbacController` / `MenuController` 就是这么漏的：消费者 1 的设备令牌 200 读到全部 11 个角色、39 条权限和整棵菜单树，并 201 建出一个角色，因为 `iam.backend_users` 的 1 号恰好是平台超管 |
| 契约 | 两个平面**不共用任何 request/response 类型**，同样由 `PlaneSeparationTests` 强制。今天两边长得一样也各写各的：后台要加的字段会变成 App 必须被告知忽略的字段 |
| 文档 | OpenAPI 出两份——`/openapi/v1.json` 只含 C 端，`/openapi/back-office-v1.json` 只含 B 端，`/connect/token` 因为给两个平面发令牌而故意同时出现在两份里 |
| 端点 | C 端端点取 id 一律走 `ICurrentUser.RequireConsumerId()`，不是 `RequireUserId()`；后台令牌得到 403 `FORBIDDEN`（不是 401：调用方已认证，请求也没什么可改的） |

### realm 这一列为什么没有 DEFAULT

默认值就是数据库替写入方**悄悄回答一个它没回答的问题**，而这恰恰是这一列要修的 bug：
一个会话本来可以在不说明它属于谁的情况下被创建。没有默认值，漏写 realm 的 INSERT 会撞在
NOT NULL 上，而不是被标成 `CONSUMER` 然后看起来一切正常。

默认值唯一的用处是让这一列能加到有数据的表上，而它并不需要：先加可空列（PostgreSQL 不重写
任何行），把已有行**逐行按证据**标注，再 `SET NOT NULL`。证据是会话已经指向的 OpenIddict
authorization——后台授权申请 `backoffice` scope，C 端设备登录不申请。
`ADD COLUMN ... DEFAULT 'CONSUMER'` 会把每一行都盖成 C 端，而活库上 22 行里有 9 行是后台会话
（2026-09-02 读）。标错的行不会响：刷新只按 `sid` 找会话，而那条路径本来就不看 realm——
它只是从此不再能被自己的主人管理，并且能被一个碰巧共用这个整数的陌生人撤销。

拿不到证据的行（authorization 已经没了）**不猜**：直接撤销。撤销后它落在每一个 partial index
和每一个活跃会话查询之外，它带的标签再也不会被任何代码路径读到，代价是它的主人重登一次。
猜一下的代价是把某人的设备交给陌生人去登出。

### 按 `sid` 走的路径故意不带 realm

`sid` 是服务端生成的 GUID，两个平面共用**一个全表唯一索引**，所以单凭 `sid` 就能定到唯一一行。
刷新、重放处理和登出手里只有 `sid`；在那里再要一个 realm 等于多造一个可能出错的东西，
而它出错的样子是「活着的会话被报成已失效」——也就是把用户的设备登出。

反过来，每一条按 `user_id` 走的路径**都**带 realm，索引也都以 realm 开头：两列永远是等值条件，
两个取值在首位不花任何代价，而一个只有 `user_id` 的前缀正是这一列要消掉的跨平面查询。

### `ICurrentUser.Realm` 从哪里来

从令牌**已授予的 scope** 推导（`backoffice` / `backoffice_pre_tenant`），**不看 id 的形状**——
和 `ValidatedTokenFacts.IsInternal`、和两条后台授权策略是同一个信号。
**不要**改成「没有后台 scope 就当 C 端」：缺失同时也是降级令牌、畸形令牌和外来令牌的样子，
基于缺失的判断是 fail-open，`BackOfficeAuthorization` 自己的注释就记着这一条。

### 现在有守卫了，因为端点那条是靠人记住的

第二次的修法是**逐个端点**改，而没有任何东西能让下一个新 controller 想起来：
`RequireUserId()` 名字更短、就在接口上、能编译、返回的正是下层 app service 想要的那个整数。
`tests/UserSvc.ArchitectureTests/ConsumerPlaneCallerIdTests.cs` 扫 `src/UserSvc.Api/Controllers`：
**back-office 目录之外的 controller 一旦取到一个没说清平面的 caller id，构建就失败**，
报错里带文件、行号和该调什么。它同时挡住 `RequireUserId()`、裸 `UserId` 读取，
以及 `BackOfficeCallerReader.Read(...).UserId`；后台目录是唯一豁免区，而目录与 namespace
被要求一致，所以没法把一个 C 端 controller 塞进豁免目录里蒙过去。

**考虑过但没做的深层修法**，连代价一起记下来：在设备登录时铸一个正向的 `consumer` scope，
再用一条授权策略要求它——这就从「纪律」变成「策略」，一个 controller 一行声明，框架来查，
方法体里忘不掉。它的代价是**不向后兼容**：已经发出去的每一个 access / refresh token 都没有
这个 scope，策略上线当天每一台已登录的 C 端设备都被拒，而且不存在一个"两者都收"的过渡窗口——
过渡期内策略等于不存在。看起来便宜的那个版本——**基于"没有后台 scope"来判断**——比它要替换的
纪律更糟，理由同上：缺失是 fail-open。真要做，顺序只能是先铸后要求。

## 依赖规则

```
Api ──────► Infrastructure ──────► Application ──────► Domain
                                        │                 │
                                   定义 Ports/        不引用任何东西
                                        ▲
                                   Infrastructure 实现它们
```

源码依赖只能由外向内。运行时是应用层调基础设施，编译期是基础设施实现应用层的接口
——两者方向相反，这就是依赖反转。

`tests/UserSvc.ArchitectureTests` 让违规**构建失败**，不靠评审时有人记得。

## 什么该进 `Ports/`

只有**跨越六边形边界**的接口。判断标准三条，任一为真即需要端口：

1. 它跨越进程边界吗？（DB / HTTP / Redis / MQ）
2. 单测里需要替换它吗？
3. 实现可能变吗？

不该进去的：`IdentifierProtector`（纯计算）、校验器、映射函数。
**`Ports/` 里只有 I/O，不是「每个类都配个接口」。**

## 领域模型：按不变量密度选择性充血

| 概念 | 形态 | 理由 |
|---|---|---|
| `UserSession` | 充血 | 轮换只能一次、重放即泄露、撤销不可复活——违反了就是安全事故 |
| `User` / `UserIdentity` | 平面 | 本质是 CRUD，规则由应用层编排 |

新增聚合前问一句：**它有需要在领域层保护的不变量吗？**没有就保持平面。

## 数据访问：EF Core 单栈

需要原生 SQL 时用 `Database.SqlQuery<T>()` / `FromSql` / `ExecuteSql`——同一个连接、同一个事务。

**不引入 Dapper**：它不会自动加入 EF 事务，且绕过全局查询过滤器（软删除、租户隔离）。
架构测试会挡住这个依赖。

## 错误契约：RFC 9457，没有信封

- 成功响应就是 DTO 本身，没有 `{ success, data }`
- 失败是 ProblemDetails + **真实 HTTP 状态码**，`errorCode` / `traceId` 走扩展成员
- `traceId` 是**裸 W3C trace id**（32 位 hex），不是完整 traceparent —— 和日志里的 `{TraceId}`、trace 后端的查询框是同一个值。框架默认会填成 `00-<trace>-<span>-01`，由 `Program.cs` 的 `CustomizeProblemDetails` 统一覆盖
- Controller 里不写 try/catch，异常冒泡到 `AppExceptionHandler`
- 状态码按**客户端该做什么反应**分组：400 改一下重提交 · 401 去重新认证 ·
  403 别再试了 · 404 不存在 · 409 状态冲突 · 422 违反业务规则 · 429 限流 · 502 上游挂了

`ErrorCodes` 里的常量是客户端契约，**只增不改**。

### 契约命名与形状

- 类型名按它在 HTTP 交互里的角色命名：`XxxRequest` / `XxxResponse`。**不要 `Dto` 后缀**——
  这个名字会成为 OpenAPI 的 schema 名，也就是每个生成客户端里的类名，`Dto` 描述的是实现模式不是东西
- **id 就是整数**，序列化成 JSON number。将来 id 真的超出 `int`，那是一次带版本的契约变更，
  不是今天用字符串去预防的理由
- 时间用 `DateTimeOffset`，序列化成 ISO 8601 带偏移量

## 认证与会话

**OpenIddict 独占 refresh token。**`UserSession` 聚合保留会话身份（`sid`）、设备信息、`LastSeenAt`
和撤销，**不再自己做轮换**。两套 refresh token 实现就是两个真相源。

这条不是偏好，是实测结论：OpenIddict 在 `SetRefreshTokenReuseLeeway(TimeSpan.Zero)` 下，重放已赎回的
refresh token 会返回 `400 invalid_grant` **并撤销该 authorization 下的每一行 token**——正是蓝图要的。

> ⚠️ **那一行配置的默认值是 30 秒，而在默认值下重放会静默成功并发出新令牌。**
> 蓝图的核心安全承诺离「悄悄不成立」只有一行配置的距离。改它之前先读 `OpenIddictRegistration`
> 里的注释。

两侧靠 `sid` claim 和 `user_sessions.authorization_id` 关联。设备登出时
`ITokenChainRevoker` 顺着 `authorization_id` 杀掉整条链。

### 撤销为什么要有两处

| 机制 | 生效范围 | 时机 |
|---|---|---|
| `user_sessions.status = REVOKED` | 刷新路径 | 立即，且是权威来源 |
| Redis 撤销集 `revoked:sid:{sid}` | **已签发的 access token** | 立即，靠 `RevokedSessionMiddleware` 每请求检查 |

只有第一处的话，「登出此设备」在 access token 过期前（最多 10 分钟）都不生效——那不是任何人要的功能。

撤销集的 TTL **等于 access token 寿命**，所以集合里只会有最近几分钟被踢掉的会话，永远不会长大，
也不需要清理任务。

`RevokedSessionMiddleware` 是网关落地前的临时位置。蓝图的终态是网关查一次、注入结果，下游零成本；
到那天，删掉这个文件就是全部改动。

## 密码：只写 Argon2id，读 Argon2id 和 bcrypt

`PasswordHasher.Verify` **按存储串自己的前缀分派**：`$argon2id$` 走 Argon2id，
`$2a$`/`$2b$`/`$2y$` 走 bcrypt，别的一律 `false`。两种格式都自带算法名，所以这不是嗅探，
**也不需要一个 `password_algo` 列**——列和串给的是同一个答案，而串不会和它旁边的摘要脱节。
（C 端 `identity.users.password_algo` 存在且无害，但它从来不是分派的前提；
后台平面没有这一列，也不欠这一列。）

理由是活库读数（2026-09-03 实测）：被替换的 Go 服务的 `uam.backend_users` 有 17 行，
**17 行全是 `$2a$10$`**。没有读路径，切换当天这 17 个运营账号拿到的 401
和输错密码完全无法区分，而唯一的信号是每次尝试一条 Error 日志。

三条强制做法：

| | 做法 |
|---|---|
| 写 | **只有 `Hash` 写密码，而它只写 Argon2id。** 没有 bcrypt 写路径，所以迁移是单向棘轮，遗留集合只会变小 |
| 迁移 | bcrypt 验过之后，由**签入流程在成功之后**重写那一行（`MigrateStoredPasswordAsync`），不在 `Verify` 里——那是读路径，错误密码和不存在的账号也会走到；也不在 gate 之前，一个被拒的请求不该写它拒掉的那一行 |
| 迁移失败 | **记日志，不抛。** 密码是对的，人已经登进来了；一次写不下去的重新 hash 是「下次再迁」，不是一次失败的登录 |

存储串是**一条分配指令**，所以两种成本都要有上限：Argon2id 的 `m/t/p`（见类注释），
bcrypt 的 work factor 上限 **12**。实测 cost 31 **不会返回**，探针得手动杀掉——
一行被篡改的数据就是一个被偷走的请求线程。同理，bcrypt 库对畸形串是**抛异常**而不是答 `false`
（实测五种异常类型），所以格式检查和 catch 都在我们这边，不指望库有这个纪律。

### 「这行读不出来」的日志要问 `IsReadable`，不能问 `Identify`

`Identify` 答的是**这个串自称是什么算法**，`IsReadable` 答的是**还有没有任何密码能验过它**。
这两个问题不一样，而拿前者当后者用会造成一次**没有任何信号的锁死**：一个 29 个字符的
`$2a$10$...`、一个 work factor 13 的行、一个 salt 解不出来的 `$argon2id$` 串，
**都自称是我们有的算法**，所以 `Identify` 会说 Bcrypt / Argon2id，日志一句话都不会写，
而它们永远验不过——每一次尝试都读成「密码错了」。

实测（跑起来的服务）：把一行改成 29 字符的 `$2a$10$`，登录答 401、日志里**一条诊断都没有**；
同一行换成不认识的前缀，Error 日志立刻出现。所以签入流程问的是 `PasswordHasher.IsReadable`。
这条正好落在**最不该沉默的那群行上**——需要迁移的那 17 行，如果哪一行在搬运中被截断，
它的主人就登不进来，而且没人看得见。

### 这个分支重新打开了一个会自己关掉的计时预言机

bcrypt cost 10 和 Argon2id 不是同一个价钱，所以 wave 7 等价化的三条路径之外多了第四条：
真 HTTP 实测，等价的三条 43.0 / 45.6 / 45.4 ms，bcrypt 行 **57.6 ms**。
换一个 agent、换一个时刻独立复测（n=40 交错采样、先热身 50 轮）：41.5 / 45.0 / 47.0 与
**57.0 ms**，样本区间不重叠（Argon2id 42.9–53.4，bcrypt 54.8–101.9）。**两遍都是 1.27 倍**。
数字、它到底泄露什么、为什么没有去填充、以及它怎么自己关掉，写在
`BackOfficePasswordTiming` 的类注释和 [`known-open.md` 第 7 条](known-open.md) 里。
**不要为了「统一」去调低 Argon2id 参数**：那会放大这个差值。

守它的测试必须是**有方向的**，而且要量**两次验证本身**，不能量两次完整签入。
`max/min` 这个统计量**对 Argon2id 的成本不是单调的**：按现在的参数 Argon2id 那条**更慢**
（实测 69.6ms 对 bcrypt 50.1ms），所以把 Argon2id 调便宜，比值先往 1.0 走、之后才回头往上；
再加上一次完整签入的固定开销会把任何比值压向 1。实测：把 `MemoryKibibytes` 减半，
端到端那个守卫从 1.39 变成 1.49，界限是 2.5，**绿的**——而它要防的那个预言机已经翻倍了。
真正会红的是 `PasswordHasherTests.TheLegacyBranchStaysWithinOneVerifyOfTheAlgorithmWeWrite`：
只比 `bcrypt / argon2id`、只量两次 `Verify`，同一个减半让它从约 1.4 变成 2.8（实测，红）。

## 失败语义：判断标准是「降级后回落到什么」

| 组件 | 失败时 | 为什么 |
|---|---|---|
| PostgreSQL | fail-closed，`/health/ready` 报不健康 | 没有库就给不出正确答案 |
| Redis · 读撤销集 | **fail-open**，放行并告警 | 这是在一个已完整验签的有效令牌之上的额外检查，**短命令牌本身就是保底** |
| Redis · 写撤销集（单设备登出） | **fail-loud**，抛 502 | 静默失败 = 被登出的设备照常能用，且无任何信号 |
| Redis · 写撤销集（全设备登出） | 全部尝试完再报错 | 第一次失败就中断会留下一半设备无撤销记录，比慢更糟 |
| Redis · 写撤销集（重放处理 / 顶替旧会话） | 记 Error 日志，不抛 | 抛出会把 OAuth 的 `400 invalid_grant` 变成 `502 ProblemDetails`，破坏令牌端点契约；而会话行已提交为 REVOKED，安全结果不依赖它 |
| Redis · 限流计数 | **fail-open**，放行并每次告警 | 见下一节。拒绝会让限流器造成它本来要防的那次故障 |
| Redis · 登录票据的一次性标记 | **fail-closed**，抛 502 | 见下面那段。这里没有任何东西垫在下面 |
| Redis · passkey 挑战状态 | fail-closed，读写都是 | 一次挑战底下没有保底可回落 |
| 通知服务 5xx / 超时 | 502 `UpstreamException` | 上游的错，不是调用方的错 |
| 通知服务 4xx | 500 类，响应体只记日志 | 是**我们**发错了；把它变成 502 等于甩锅给上游 |
| 产品主数据不可达（今天恒不可达） | 租户**读**：fall-open；供应商**挂载写**：502，什么都不写 | 同一个 null，两种正确行为，因为方向由调用方决定而不是由占位实现决定 |

同一个 Redis，读撤销集 fail-open、写撤销集 fail-loud——因为读有保底、写没有。

### 这张表里的方向不一致是**有意的**，别去"统一"它

同一个进程、同一个 Redis、同一个异常类型，三个组件三个方向：

- **登录票据的一次性标记 fail-closed。** 它是**唯一**知道一张票是否已经花掉的东西。
  Redis 抖动期间放行等于让一张被截获的票在这段时间里重新变成可重放的——那正是这个组件存在的
  全部理由。
- **撤销集的读 fail-open。** 它是叠在一个**已经完整验签的有效令牌**之上的额外检查，
  而短命令牌本身就是保底。
- **限流 fail-open。** 它保护的是那些依然会被认证、校验和审计的端点；Redis 抖动期间全拒
  会同时打掉登录、注册和发码，也就是限流器亲手造成它本来要防的那次故障。

判断标准只有一句：**降级之后回落到什么**。下面有东西垫着 → 可以 fail-open；
自己就是最后一道 → fail-closed。将来一定有人来"修"这个不一致，这一节就是拦住他的东西。
`RedisSingleUseMarkerStore` 的类注释里也写着同一句话。

## 限流：数的是失败，不是尝试

三件事写在这里，因为每一件都被改错过一次：

1. **密码门数的是失败次数，成功会清零；OTP 门数的是尝试次数。**
   差别在一次尝试的成本：一次 OTP 尝试是一通打给企业目录的 HTTP 调用外加一条真发出去的验证码，
   所以"到达"本身就值得计数；一次密码尝试只花我们一次 hash，所以那里的预算是**锁定**，
   用 `PeekAsync` 读、不 `TryAcquireAsync` 花。曾经在这里计数，于是**正确的密码也在花预算**，
   配好的"每分钟 10 次"描述的是一个会打错字的人，而不是当初照着五次锁定挑的那组数字。
2. **只有 per-mailbox 那份预算被成功清零，per-source 那份故意不清。**
   清了就等于任何持有一个可用后台账号的人可以无限喷洒：失败四次、登自己的、重复。
   per-source 这个维度存在的意义正是它能扛住"攻击者自己也有一个合法凭据"。
3. **`RemoteIpAddress` 为 null 时 per-source 预算自己关掉，而不是共用一个桶。**
   不然每一个拿不到对端地址的请求都数进同一个计数器，头几个就把其余全部锁死——
   一个说不出自己主体是谁的预算不是预算。

后两条各有一个直接后果，都值得知道：

- **`TestServer` 没有 socket**，所以集成测试里 `RemoteIpAddress` 恒为 null，整个套件的
  per-source 预算是关着的。好处是 CI 不会把自己限流死（实测：14 个邮箱 14 次失败登录写了 14 对
  `backoffice-sign-in` 计数器、一个 `backoffice-sign-in-ip` key 都没有）；代价是这个维度
  **除非某个测试专门要一个地址，否则完全没有端到端覆盖**。所以 `UserSvcApplicationFactory`
  有一个 `peerAddress` 参数，per-host opt-in，今天恰好只有一个测试用它。
- **本服务没有任何地方注册 `UseForwardedHeaders`**，所以 `RemoteIpAddress` 是网关的地址。
  跑在网关后面时，每一个请求共用同一份 per-source 预算——这个控制项在那种部署下等于没有。
  要补的是宿主层把网关放进 `KnownProxies`，不是在某个 app service 里私下再解一遍
  `X-Forwarded-For`：那会变成第二套信任模型，审计行记网关、限流信任伪造的头，
  攻击者每个请求换一个头就换一份新预算。两者要一起改。

## 生产环境会拒绝启动的配置

不是缺陷，是设计。宁可启动失败，也不要带着错误配置静默运行：

| 配置 | 缺失时 |
|---|---|
| `ConnectionStrings:Default` | 抛，不启动 |
| `Redis:Configuration` | `[Required]` 拒空串——**故意不在 `appsettings.json` 里给默认值**，一个 `localhost` 默认值比缺失更糟 |
| `Notification:BaseAddress` | 同上；且**必须以 `/` 结尾**，否则 `HttpClient.BaseAddress` 会吞掉最后一段路径 |
| `AuthToken:SigningCertificateThumbprint` / `EncryptionCertificateThumbprint` | 非 Development 拒绝启动。用临时密钥意味着每次重启作废全部令牌，且两个副本互相不认——一次看起来像随机 bug 的故障 |

`DevAuthenticationHandler` 只在 Development 注册，用 `X-Dev-User-Id` / `X-Dev-Session-Id` 伪造身份，
**不做任何验证**。它和 OpenIddict 并存，所以本地 curl 和集成测试不受影响。

## 中间件顺序里两处不能动的地方

`Program.cs` 的管道顺序不是风格问题，有两处错了会静默出错：

1. **`UseSerilogRequestLogging()` 必须在 `UseExceptionHandler()` 之前（最外层）。**
   放在后面，它看到的是仍在飞的异常，会把请求记成 500——而异常处理器接下来会把它变成 400。
   于是每一次普通的校验失败都在请求日志里长得像一次服务端故障，所有基于该日志的 SLO 看板
   都会把我们自己的 4xx 读成我们自己的宕机。
2. **`RevokedSessionMiddleware` 必须在认证之后、授权之前。** 之前没有 `sid` 可读；之后
   一个已撤销的会话可能已经通过了某条授权策略。

## 一个缺失的能力只能弄坏它自己

这条规则被违反了三次，每次的表现都不一样，所以值得写下来：

1. **拒绝式占位放在了「顺带查询」的读路径上**——它在每次租户上下文解析都要经过的地方抛异常，
   于是整个租户后台不可用。占位实现要在**能力缺失处**失败，不是在被顺带碰到处。
2. **`ValidateOnStart` 用在了没人配的配置段上**——一个没有微信 AppId 的部署（也就是今天的每个部署）
   直接起不来，24 个和微信毫无关系的集成测试全在启动时死掉。
3. **构造期读 `IOptions<T>.Value`**——`.Value` 才是跑 DataAnnotations 校验的地方。在构造函数里读它，
   意味着这个类**仅仅被构造**就会抛；而一个 app service 把四家提供商都放进构造函数，
   于是任一家缺凭证就让四家的端点全部 500，报的还是别人家的密钥。

三条对应三个做法：

| | 做法 |
|---|---|
| 占位实现 | 在能力真正被调用处拒绝，不在被解析处 |
| 配置段 | `ValidateDataAnnotations()` 但**不** `ValidateOnStart()`——校验推迟到第一次读，也就是第一个用到它的请求 |
| `IOptions<T>` | 在**使用点**读 `.Value`，不在构造期。`.Value` 有缓存，没有重复代价 |
| 多能力共处一个服务 | 注入 `Func<T>` 而不是 `T`，让构造一个不牵连其余 |

配置缺失映射为 500 `NOT_CONFIGURED`（不是 `INTERNAL_ERROR`），`detail` 里带上缺失的段名——
运维读到它就知道去看密钥，而不是去读代码。

**只有一个例外，而且是反过来的：令牌端点。** 那里的调用方是匿名的，同一句话会把这个部署的
密钥名清单交给一个陌生人。它答一个笼统的 `server_error`（不是 `invalid_grant`——问题在部署，
不在凭据；`invalid_grant` 会让运维去查客户端 bug），段名进日志。

### 后来又被违反了四次，所以现在有守卫

上面三条是靠人记住的，然后又出了四次：第 4、5 次是 `OAuthStateService` 与
`SocialBindingTokenService` 在**字段初始化器**里读 `.Value`，害得一个纯数据库的解绑接口报 500
说签名密钥不对；第 6 次是 `RedisSingleUseMarkerStore` 同样的形状；第 7 次是
`Program.cs` 少了 `Func<TestWhitelistAppService>` 的注册，容器直接构建不出来。

所以现在有 `tests/UserSvc.ArchitectureTests/OptionsReadSiteTests.cs`：它扫 `src/`，
**任何新增的「字段初始化器里读 `IOptions<T>.Value`」都会让构建失败**。文件里列了当前仍存在的
9 处（都压在 `ValidateOnStart()` 的段上，所以是形状不是故障），并且第二个测试要求这张清单只能变短
——修好了却还留在清单里，会让守卫看起来比实际更紧。

修法就是上表那一行：把字段换成同名的表达式体属性，调用点一行都不用改。

**第 7 次是在"记下前四次"的那份文档写完几个小时之后发生的**，就在同一个仓库里。
这件事本身就是守卫存在的论据：一条规则被写下来、被读过、被同意，然后当天再被违反一次。
凡是"靠人记住"的约束，这个项目现在的答案都是给它加一个扫源码的测试——
`ConsumerPlaneCallerIdTests` 是同一个理由的第二个例子。

## 测试宿主不要向操作系统要密钥

`AuthToken:UseEphemeralKeys` 存在的原因值得记下来：探测「能不能打开 CurrentUser/My 存储」
不足以判断能不能用它。在 macOS 上，测试宿主里这个存储**打开成功，第一次使用私钥时阻塞**——
整个测试套件挂死在令牌生成里，没有异常、没有超时，看起来像 OpenIddict 死锁。

任何非交互宿主（集成测试、CI、容器）都应该把它设成 `true`，别再问操作系统要许可。

## 消息：有 outbox，没有投递器

Go 服务不用 RabbitMQ，本服务也不引。但 `identity.outbox_messages` 保留，领域事件仍然**在业务事务里
原子落表**（`DomainEventOutboxInterceptor`）。

抽取放在拦截器而不是 `UnitOfWork` 里，是因为共享同一个 `DbContext` 的库——OpenIddict 的 EF store
就是——会直接调 `SaveChanges`。留在 `UnitOfWork` 里会在那些保存上静默跳过 outbox，事件搁在实体上没人管，
而且不报任何错。

当前没有消费者，所以 outbox 是一份持久事件日志（重放检测这类安全事件值得留痕）。等真正的集成机制定下来，
加一个投递器读它即可，业务代码一行不动。那个投递器最可能就是下一节这个队列的第一个 handler——
它要的正好是「带重试、和造成它的那次写在同一个事务里入队」，见
[`known-open.md` 第 9 条](known-open.md)。

## 异步任务：`identity.task_queues`，机制齐、默认关、还没有 handler

Go 的 `internal/service/task`（runner + fixer + 仓储六个操作）整体移过来了，队列表是
`identity.task_queues`（`db/0014_task_queues.sql`，脚本头里逐条写了 schema 选择、为什么物理删、
索引为什么不照抄 Go 的）。RabbitMQ 两边都不引：**这张表给的正是 broker 给不了的东西**——
造成这份工作的那一行和记录这份工作的那一行，在同一个事务里提交。

今天**没有任何 handler**，因此也没有生产者和消费者。Go 那边唯一的 handler 是 FCM 主题同步，
按用户的明确划分属于 notification service，所以这里只移机制。缺口和它的代价见
[`known-open.md` 第 9 条](known-open.md)。

### `Tasks:WorkerCount = 0` 是出厂默认，也是 kill switch

runner 和 reclaim 两个 `BackgroundService` 各自读它，为 0 就直接 `return`：不轮询、不起定时器、
不占连接，各打一行日志说自己关着。这一条让一个镜像服务两种部署形态（决策 02）：API pod 留 0，
worker pod 给正数，撤掉 worker 是改配置而不是发版。

**这个检查必须在 runner 自己里面。** Go 把它放在调用方（`fcm_topic_sync/lifecycle.go:29`），而
`task/runner.go:45` 反过来把 `WorkerCount <= 0` 提升成 1 —— 于是第二个队列、第二个 lifecycle、
或者任何直接从配置构造 runner 的测试，都会在配置说"不要 worker"的地方拿到一个活的 worker。

实测（2026-09-03，真宿主 + 活库 `lion_user`）：注册了 handler、表里躺着一行已到期的任务、
不给任何 `Tasks__*` 覆盖 —— 12 秒零投递，`popped_by` 是空串，`pg_stat_user_tables.idx_scan`
一次没动。只把 `Tasks__WorkerCount` 改成 1，同一批行立刻被领走、处理、删掉。

### handler 必须幂等，而且 Delete/ReArm 归 handler 不归 runner

投递是 at-least-once，而且原因是结构性的：handler 先做副作用、再记录做过了，这两步之间 pod 会被
OOM kill。行还是 popped，reclaim 放开它，**同一个任务带着已经做完的副作用再来一次**。

`HandleAsync` 因此返回裸 `Task`，不返回结果让 runner 去解释。三个理由：
① handler 自己的写和它的 `DeleteAsync` 可以共用一个事务，runner 事后再删就必然是第二个事务，
那个崩溃窗口就永久关不掉了；② "失败"不是一件事 —— payload 坏了要永久 Delete、远端 503 要带
backoff ReArm、部分成功要只重试剩下的，只有 handler 分得清；③ 重试预算是领域状态，
只有 handler 知道这一次有没有取得进展。

**runner 对异常只做一件事：记日志。** 行留在 popped，`Tasks:StalePoppedTimeout` 之后由 reclaim
放开，所以抛异常等于选了「慢速重试」——**而且这个重试没有上限**。实测：一个每次都抛的 handler
在 40 秒里被投递 11 次，`Tasks:MaxAttempts=2` 完全没有作用，因为**这条路上没有任何东西在计数**。
`MaxAttempts` 只是一个配置值加一行启动日志；真要生效得靠 handler 自己的计数器（自己的表或
`payload_json`）加自己的 `DeleteAsync`。终态是删除而不是留一行：那个 `(queue_name, task_id)`
槽位必须腾出来，否则同一个对象再也不能重新入队。

### stale 回收故意不碰重试计数，代价是容忍重复执行

reclaim 只把 popped 超过 `StalePoppedTimeout` 的行放开，其余一概不动，也不按队列过滤（崩掉的 pod
在服务哪个队列，它没留下任何痕迹）。不动 attempt 计数是决定不是遗漏：崩之前已经做过副作用的
worker 不该因为崩了而丢预算，崩之前什么都没做的 worker 也没花掉预算。`deliver_on` 同样不动——
Go 在这里写 `NOW()`，等于把等得最久的那一行排到本优先级带的最后。

代价写清楚：**reclaim 分不清「worker 死了」和「worker 还在跑，只是比超时慢」**，于是它会放开一个
仍在执行中的任务的行。实测（`TaskTimeout=0`、`StalePoppedTimeout=4s`、一个不返回的 handler）：
同一行 15 秒里被投递 4 次（每 5 秒一次，也就是超时加一个 reclaim tick），4 个副本同时在跑，
把这个 pod 的 worker 槽位全占满，之后队列里别的任务一个也不动。

所以 **`Tasks:TaskTimeout` 必须明显小于 `Tasks:StalePoppedTimeout`**，出厂是 5 分钟对 10 分钟：
差出来的那 5 分钟是"被取消的 handler 收摊"的窗口。两个值最初都写成 10 分钟（等于没有余量），
是这一轮实测出来才改的，`TaskQueueOptionsTests` 现在守着它。handler 拿到的 `CancellationToken`
只表示"你超时了"，**永远不表示"要关机了"**：关机不打断在飞的任务，只停止领新的然后等
（`Tasks:DrainTimeout`，5 秒，Go 的 `APP_SHUTDOWN_TIMEOUT`；这两个 hosted service 在 `Program.cs`
里注册在最后，所以反序停止时它们最先被 drain）。

### 时钟只有一个，是 PostgreSQL 的

入队、re-arm、stale cutoff、`deliver_on <= now()` 全部由数据库求值，port 收 `TimeSpan` 而不是绝对
时刻。Go 混用了两个（`Pop` 比服务器的 `NOW()`，`ReArmTx` 和 `RecoverStale` 用 pod 的 `time.Now()`）：
pod 时钟漂多少，每个 backoff 窗口和每个 cutoff 就错多少，而症状（重试早了/晚了）读起来像调参问题。

### 部署顺序：DDL 先行，代码后发。发反了会很吵，但看得见

决策 14 在这里有具体后果。实测：在 `db/0001`–`0013` 已应用、`0014` 没应用的库上启动 —— 宿主正常起、
`/health/live` 与 `/health/ready` 都 200，队列每个 short poll 打一条 Error，指名
`42P01: relation "identity.task_queues" does not exist`。这是**故意吵**：默认 2 秒一条，
一天四万多条；但一个静默降级的队列会让人以为任务已经跑过了。补上脚本即恢复，不用重启。

`Tasks` 段本身写坏也只弄坏队列。实测四种坏法（`ShortPollInterval=banana`、`WorkerCount=lots`、
`WorkerCount=4096` 越界、整段给成一个标量）：宿主都起得来、consumer 文档 31 个路径都在、
真实请求照样返回带 `errorCode` 和 `traceId` 的 RFC 9457 400，只有队列关着，
并打一行指名 `Tasks` 段的 Error。第四种（标量）绑成默认值，于是走 kill switch 那条路。

## 日志抽象可以进内环，日志实现不行

`Microsoft.Extensions.Logging.Abstractions` 允许出现在 Application 层；`Serilog` 被守卫禁止。
一个说不出自己哪里出错的应用服务，耦合程度比依赖 `ILogger<T>` 更糟。

## 数据库

`db/README.md`。要点：**应用永不改库**，DDL 手动先行，脚本幂等。

### 门禁 04 一直是装饰品，EF 模型与手写 DDL 的漂移就是这么攒起来的

`azure-pipelines.yml` 里的门禁 04 生成一份 `model.sql`，然后 `echo "Review model.sql against
db/*.sql"`——**它从不 diff，也从不失败**。一个不会红的门禁不是门禁，漂移攒了七个 wave 才被人
逐表对齐。

而且那条命令今天根本跑不起来（实测，HEAD `c6914ce`）：门禁 01 用 `-c Release` 构建，门禁 04 的
`--no-build` 却去 `bin/Debug` 找 `deps.json`，退出码 129。`db/README.md` 里那条（不带
`--no-build`）是能跑的那条：

```bash
dotnet dotnet-ef dbcontext script -p src/UserSvc.Infrastructure -s src/UserSvc.Infrastructure
```

startup project 必须是 `UserSvc.Infrastructure`：`Microsoft.EntityFrameworkCore.Design` 只被它
引用，换成 `UserSvc.Api` 会直接报 "doesn't reference Microsoft.EntityFrameworkCore.Design"。
已知的、有意的差异列在 `db/README.md` 的例外表里；新增例外要写清"为什么模型表达不了"。

## 发码接口的两个「是否已注册」枚举预言机

`POST /api/v1/verification/send` 会按 `purpose` 走不同的前置校验
（`VerificationAppService.EnsureTargetSuitsPurposeAsync`），其中两个 purpose 的**错误码本身**
就把「某个手机号/邮箱是否已注册」告诉了一个匿名调用方。这是从 Go 服务原样移植的**客户端契约**，
不是缺陷；写在这里，是为了让「要不要关」由拥有客户端契约的人**一次性**决定，而不是被每个 reviewer
反复重新发现。

**泄露了什么、对谁泄露、在哪些 purpose 上：**

| purpose | 命中已注册时 | 命中未注册时 | 因此暴露给匿名调用方的事实 |
|---|---|---|---|
| `reset_password` | 正常发码（200） | `400 UNREGISTERED` | 该标识符**是否已注册**（成功=已注册，报错=未注册） |
| `bind` | `409 IDENTITY_ALREADY_BOUND` | 正常发码（200） | 该标识符**是否已绑定/已注册**（报错=已注册，成功=未注册） |
| `auth` / `backoffice_auth` | 不查库，无差异 | 不查库，无差异 | 无——注册与验证码登录共用，发码时本就不该知道目标是否存在 |
| `backoffice_reset_password` | 正常发码（200） | **也是 200，同一句 `Verification code sent successfully`**，且不写 code 行、不发信 | 错误码这一层**没有**——这是本表唯一一个有意关掉的，理由与残留的两条侧信道见下一节。说实话的地方只剩**提交那头**（`POST /api/v1/back-office/auth/password-reset` 仍答 `400 UNREGISTERED` / `403 ACCOUNT_DISABLED`），而走到那里必须先持有一张对着该邮箱铸出来的 ticket |

两个路由都是 `[AllowAnonymous]`，所以泄露对象是**任意匿名调用方**。`/verify` 不做身份查询，
不在此列。

**今天真正约束这个抓取的是什么：**风控**排在前置校验之前**跑
（`SendVerificationCodeAsync` 里顺序是 限流 → 载荷校验 → 风控 → purpose 前置校验）。也就是：
每 IP 的发码预算（默认 100/min、500/hr）与每目标/每设备的风控节流，都在那次「会暴露是否注册」的
查库**之前**就已生效。攻击者想逐个枚举，先撞的是这套节流，而不是预言机本身。

**关掉它对客户端的代价：**

- 移动端**现在就分支**在这两个错误码上：重置密码流程用 `UNREGISTERED` 提示「该账号未注册」，
  绑定流程用 `IDENTITY_ALREADY_BOUND` 提示「已被占用」。直接删掉会让这两个提示消失，属于**破坏性**
  契约变更。
- 要「正确」关闭，得让**所有接收标识符的流程**统一成一句「若该地址已注册，验证码已在路上」
  式的无差别应答——不只是本接口，还包括 auth 切片里的**注册**与**绑定**接口，它们今天从别的路径
  漏出同一个信号。只在本接口关、别处不关，等于什么都没买到。因此这是一次**跨接口、跨所有生成客户端**
  的协同契约变更，得连带 OpenAPI schema 与各端分支逻辑一起改。
- 决策归属：拥有客户端契约的人。在此之前，保留现状是**有意**的，別在移植/评审中单方面改动。

### `backoffice_reset_password` 为什么反过来关掉了

上面两个 purpose 保留预言机的理由是「客户端已经在分支」。后台自助改密这条**没有这个理由**，
所以 wave 9 接通它的时候把答案改成了无差别的那一句：不合格的目标（没有后台账号、账号已停用）
拿到和合格目标**完全相同**的 200 与同一句话，并且不写 code 行、不发信——因此也拿不到 ticket。

**为什么这条可以自己决定，而那两条不行。**

- 它是最新的 purpose，**没有任何已有客户端分支在它的错误码上**。活库实测（2026-09-02）：Go 服务的
  `uam.verification_codes` 里 `backoffice_reset_password` 一共 **4 行**、其中 3 张 ticket 被铸出并
  消费掉，时间集中在 2026-08-03 与 08-05；整张表 13 行。这是开发期自测的量级，不是线上流量。
  （同期 `uam.iam_audit_logs` 里没有 `SELF_PASSWORD_RESET` 行，但那张表最早的行是 2026-08-10，
  所以它证明不了任何事，别拿它当反证。）
- 它问的表是**运营目录**，不是客户库。匿名调用方逐个确认「某个企业邮箱是不是运营账号」，
  得到的是一份**对后台控制台有权限的人名单**——企业邮箱本身是可猜的，所以这一步把可猜的命名空间
  换成了确定的特权用户清单。这比 C 端「这个人是不是客户」重一档。
- **决定性的一条是内部一致性。** 同一个平面的密码门（`POST /api/v1/back-office/auth/login`）
  已经为关掉同一个预言机付过钱：未知邮箱与错密码的响应完全相同，`BackOfficePasswordTiming`
  还专门在 miss 上补跑一次 Argon2id，因为实测未知邮箱 3.6ms、错密码 52.3ms。发码这头答
  `UNREGISTERED`，等于从另一个端点把那笔钱原样退回去——两个端点问的是同一张表的同一个问题。

**前端为此少了什么：**只少了「该邮箱不是运营账号」和「你的账号已停用」这两句提示。两种情况下
用户该做的事本来就一样——找管理员（管理员重置那条路一直在，
`POST /back-office/tenants/{t}/{c}/members/{id}/reset-password`）——所以前端没有丢失任何它真的
需要的能力。提交那头仍然说实话，而那时调用方已经证明了自己控制这个邮箱。

**仍然漏的两条，实测（2026-09-02，本机跑起来的服务）：**

1. **时间。** 三种状态都答 200，但被静默拒绝的两种各 ~5–6ms（两次查库），合格目标 ~10–17ms
   （多一次 code 行写入与一次通知调用；这里的通知服务是本机 stub，真实通知服务在网络那头，
   差距会更大）。比密码门当初 14 倍那种差距小，也比它噪声大，但它在。
   **能带走的是比值，不是毫秒数。** 同一台机器换个时刻独立复测（n=30，交错采样，先热身）：
   静默 2.0 / 2.3ms，合格 4.6ms——绝对值差一半，**比值还是约 2 倍**。
   谁在别的机器上量出别的毫秒数，那不是这条记录错了。
2. **通知服务停机的窗口里预言机完整回来。** 合格目标在写完 code 行后发信失败，答
   `502 SEND_FAILED`；不合格目标照样 200。实测（通知服务不可达）：合格目标 502、耗时 4.3s，
   不合格目标 200、耗时 5–13ms。**没有把 502 也吞掉是有意的**：对一个真的在改密码的人，
   「发不出去」是他唯一需要的信息，吞掉它等于让停机期间每个人都收到一句「验证码已在路上」
   然后永远等下去。停机是响的、短的，契约是永久的。

**约束这次抓取的仍然是排在前面的节流**，而且这次它是主要防线：per-IP 发码预算（100/min、500/hr）
与风控的**每目标/每设备**计数都在查库之前跑完，风控计数在 Redis 里、每次尝试都数，与最后是否
真的发出验证码无关——所以静默拒绝不会让枚举变便宜。提交那头另有自己的 per-source 预算
（`BackOffice:PasswordResetPerSourcePerMinute`/`PerHour`，默认 100/min、500/hr，
dimension `backoffice-password-reset-ip`，与登录门、发码门各自独立）。

> Go 服务这条路由的 per-IP 预算是**每小时 3 次**，本服务**故意没有照抄**：本进程不注册
> `UseForwardedHeaders`，跑在网关后面时每个请求共用同一个对端地址（见前面限流那节），
> 3/hr 就不是节流而是「整个运营群体每小时只能改 3 次密码」的停机。
