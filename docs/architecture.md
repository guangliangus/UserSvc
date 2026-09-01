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
