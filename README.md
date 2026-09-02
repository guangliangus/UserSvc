# user-svc

身份与访问服务（C 端身份 + B 端 IAM，两个限界上下文、一个部署单元）。
.NET 10 · PostgreSQL · 六边形骨架 + 垂直切片。

**架构蓝图**（20 条决策及其代价）：<https://claude.ai/code/artifact/f2d16240-1947-48aa-b58d-46c24258d4a0>
**代码里被强制执行的约束**：[`docs/architecture.md`](docs/architecture.md)

## 目录

```
src/
  UserSvc.Domain/          实体与领域规则；不引用任何东西
    Users/                   User, UserIdentity —— 平面
    Auth/                    UserSession —— 充血（会话身份 / 设备 / 撤销）+ 领域事件
  UserSvc.Application/     用例、契约、校验器、端口；只引用 Domain
    Ports/                   按子域分：Users / Auth / External / Platform
    Features/                垂直切片：Profile / Sessions
    Security/                IdentifierProtector —— 纯计算，刻意不是端口
    Errors/                  错误码与异常层级（携带 HTTP 状态与 inner exception）
  UserSvc.Infrastructure/  适配器；引用 Application 并实现它的端口
    Persistence/             EF DbContext、仓储、outbox 拦截器、OpenIddict 模型约定
    Auth/                    OpenIddict 令牌链撤销、过期清理
    Platform/                Redis 撤销集、系统时钟
    External/                通知服务 HTTP 客户端（弹性管道）
  UserSvc.Api/             宿主
    Auth/                    OpenIddict 注册、重放事件处理器、撤销中间件、开发期认证
    Controllers/             Profile / Sessions / Token
    Errors/                  ProblemDetails 映射
tests/
  UserSvc.ArchitectureTests/  ★ 依赖方向、分层约定、源码语言的机器强制
  UserSvc.UnitTests/          聚合与 AppService，端口全 mock
  UserSvc.IntegrationTests/   Testcontainers：真 Postgres + 真 Redis + 真代码路径
db/                        手动执行的幂等 DDL（0001-0003 identity / 0004-0007 iam）
```

## 跑起来

依赖 PostgreSQL 和 Redis。**本机 5432 / 6379 通常已被其他容器占用**，所以下面直接用现有的那套
（库 `lion_user`，本服务只占 `identity` 和 `openiddict` 两个 schema，与 `uam` 互不干扰）：

```bash
# 1. DDL 手动先行（幂等，可反复执行）
export PGPASSWORD=123456
psql -h localhost -p 5432 -U dev -d lion_user -f db/0001_identity.sql
psql -h localhost -p 5432 -U dev -d lion_user -f db/0002_openiddict.sql

# 2. 起服务
dotnet run --project src/UserSvc.Api        # http://localhost:5080
```

连接串在 `appsettings.Development.json`。**`appsettings.json` 里刻意没有 `Redis:Configuration`
和 `Notification:BaseAddress`**——它们是 `[Required]` 且启动时校验，缺失会拒绝启动，而一个
`localhost` 默认值会让生产静默连错机器。

API 文档：<http://localhost:5080/swagger>　OIDC 发现：<http://localhost:5080/.well-known/openid-configuration>

### 拿一个令牌

```bash
# 设备登录（自定义 grant）
curl -s -X POST http://localhost:5080/connect/token \
  -d 'grant_type=urn:usersvc:params:oauth:grant-type:device' \
  -d 'client_id=usersvc-app' \
  -d 'user_id=1' -d 'device_id=dev-A' -d 'device_name=iPhone 15 Pro' -d 'platform=IOS'

# 带上 access token
curl -s http://localhost:5080/api/v1/user/profile -H "Authorization: Bearer $AT"

# 列出登录设备 / 踢掉一台
curl -s http://localhost:5080/api/v1/user/sessions -H "Authorization: Bearer $AT"
curl -s -X DELETE http://localhost:5080/api/v1/user/sessions/$SID -H "Authorization: Bearer $AT"
```

开发期也可以绕过 OAuth，用两个头伪造身份（仅 Development）：

```bash
curl http://localhost:5080/api/v1/user/profile -H 'X-Dev-User-Id: 1' -H 'X-Dev-Session-Id: sid-1'
```

## 验证

```bash
dotnet build UserSvc.slnx      # 零警告（TreatWarningsAsErrors）
dotnet test  UserSvc.slnx      # 单元 + 架构守卫
```

## 当前进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 骨架 + CI 门禁 + 架构守卫 | ✅ |
| 1 | 用户档案 + 注册 + 头像 | ✅ |
| 2 | 验证码（Redis 限流、调通知服务） | ✅ |
| 3 | 认证核心（OpenIddict、设备会话、令牌轮换） | ✅ |
| 4 | 第三方身份（微信 / Firebase / LINE / Passkey） | ✅ Passkey 完整可用；三家社交为真适配器，等凭证 |
| 5 | 后台账号 + RBAC + 租户 | ✅ 含后台登录（密码门可用；OTP 门等上游凭证） |

阶段 3 已端到端验证：设备登录 → 刷新轮换 → **重放已赎回的 token 触发整链撤销**，会话行标记
`TOKEN_REPLAY`、两条 outbox 行在同一事务落表、Redis 撤销集写入、被撤销会话的 access token
在下一个请求上立即 401 `SESSION_REVOKED`。

## 还没接的东西

- **凭证**：微信 AppId/Secret、Firebase ProjectId、LINE ChannelId、reCAPTCHA Secret、
  Azure Blob 连接串。**代码全部写好了**——协议是公开的，缺的是密钥。缺哪个只影响哪个端点，
  返回 500 `NOT_CONFIGURED` 并指名缺失的配置段
- **授权快照与网关注入**：RBAC 表尚不存在，网关产品未定——现在建等于建了要重写
- **Outbox 投递器**：事件已原子落表，但没有消费者也没有 broker（Go 服务不用 RabbitMQ）。
  等真正的集成机制定下来再加，业务代码不受影响
- **通知服务的服务间认证**：不确定对方是否要令牌。DI 里 `IHttpClientBuilder` 特意留在局部变量，
  一个 `DelegatingHandler` 就能挂上去
- **`SendDirectPath` 是猜的**：拿不到通知服务的 OpenAPI 文档
- **`ITenantMasterDataDirectory`**：租户主数据在本服务之外，是唯一剩下的拒绝式占位
- **LionTravel OTP 的上游契约是推测的**：规格只给了方法名，真实的请求/响应形状拿不到，
  客户端里每一处假设都标注了
