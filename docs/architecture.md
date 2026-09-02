# 架构约束

完整设计与每条决策的理由见**架构蓝图**：
<https://claude.ai/code/artifact/f2d16240-1947-48aa-b58d-46c24258d4a0>

本文只列**代码里被强制执行**的部分。改动这些约束前，先改蓝图。

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

## 失败语义：判断标准是「降级后回落到什么」

| 组件 | 失败时 | 为什么 |
|---|---|---|
| PostgreSQL | fail-closed，`/health/ready` 报不健康 | 没有库就给不出正确答案 |
| Redis · 读撤销集 | **fail-open**，放行并告警 | 这是在一个已完整验签的有效令牌之上的额外检查，**短命令牌本身就是保底** |
| Redis · 写撤销集（单设备登出） | **fail-loud**，抛 502 | 静默失败 = 被登出的设备照常能用，且无任何信号 |
| Redis · 写撤销集（全设备登出） | 全部尝试完再报错 | 第一次失败就中断会留下一半设备无撤销记录，比慢更糟 |
| Redis · 写撤销集（重放处理 / 顶替旧会话） | 记 Error 日志，不抛 | 抛出会把 OAuth 的 `400 invalid_grant` 变成 `502 ProblemDetails`，破坏令牌端点契约；而会话行已提交为 REVOKED，安全结果不依赖它 |
| 通知服务 5xx / 超时 | 502 `UpstreamException` | 上游的错，不是调用方的错 |
| 通知服务 4xx | 500 类，响应体只记日志 | 是**我们**发错了；把它变成 502 等于甩锅给上游 |

同一个 Redis，读 fail-open 写 fail-loud——因为读有保底、写没有。

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

## 两个身份平面共用一个令牌颁发者，所以 `sub` 不能单独用

`identity.users` 与 `iam.backend_users` **各自独立编号**，而两个平面由同一个 OpenIddict 颁发令牌，
所以后台运营 5 号与 C 端用户 5 号是两个人、同一个整数，且后台的 access token 能满足
一个裸 `[Authorize]`。

实测（wave 7 审计，跑起来才发现的）：`sub=1` 的后台令牌能 200 读到 C 端用户 1 的
`GET /api/v1/user/profile`；`DELETE /api/v1/account` 会关掉那个 C 端账号并踢掉他所有设备。
请求本身没有任何畸形。

两条强制做法：

| 层 | 做法 |
|---|---|
| 会话表 | `identity.user_sessions.realm`（`CONSUMER` \| `BACKOFFICE`），聚合与仓储只收 `SessionSubject`，没有默认值也没有回落 |
| 端点 | C 端端点取 id 一律走 `ICurrentUser.RequireConsumerId()`，不是 `RequireUserId()`；后台令牌得到 403 `FORBIDDEN` |

`ICurrentUser.Realm` 由令牌**已授予的 scope** 推导（`backoffice` / `backoffice_pre_tenant`），
不看 id 的形状——和 `ValidatedTokenFacts.IsInternal`、和两条后台授权策略是同一个信号。
**不要**改成「没有 act claim 就当 C 端」：缺失同时也是降级令牌、畸形令牌和外来令牌的样子，
基于缺失的判断是 fail-open。

`sid` 是例外，且是有意的：它是服务端生成的 GUID，两个平面共用一个全表唯一索引，所以单凭 `sid`
就能定到唯一一行。刷新与重放路径手里只有 `sid`，在那里再要一个 realm 等于多造一个可能出错的东西，
而它出错的样子是「活着的会话被报成已失效」，也就是把设备登出。

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
加一个投递器读它即可，业务代码一行不动。

## 日志抽象可以进内环，日志实现不行

`Microsoft.Extensions.Logging.Abstractions` 允许出现在 Application 层；`Serilog` 被守卫禁止。
一个说不出自己哪里出错的应用服务，耦合程度比依赖 `ILogger<T>` 更糟。

## 数据库

`db/README.md`。要点：**应用永不改库**，DDL 手动先行，脚本幂等。

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
| `backoffice_reset_password` | 目前恒 `501 NOT_IMPLEMENTED` | 同左 | 暂无（B 端身份平面未移植）。一旦 `assertBackOfficeResetTarget` 落地，它会用 `UNREGISTERED` / `ACCOUNT_DISABLED` 暴露**后台**身份的同类事实，届时本表要补一行 |

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
