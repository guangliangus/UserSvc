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
    Auth/                    UserSession —— 充血（轮换 / 重放检测 / 撤销）
  UserSvc.Application/     用例、DTO、校验器、端口；只引用 Domain
    Ports/                   按子域分：Users / Auth / External / Platform
    Features/                垂直切片：Profile / Sessions
    Security/                IdentifierProtector —— 纯计算，刻意不是端口
    Errors/                  错误码与异常层级（携带 HTTP 状态）
  UserSvc.Infrastructure/  EF DbContext、仓储、占位适配器、DI
  UserSvc.Api/             宿主：Controllers、ProblemDetails、三探针
tests/
  UserSvc.ArchitectureTests/  ★ 依赖方向与分层约定的机器强制
  UserSvc.UnitTests/          聚合与 AppService，端口全 mock
db/                        手动执行的幂等 DDL
```

## 跑起来

```bash
# 1. 数据库
docker run -d --name usersvc-pg -p 5432:5432 \
  -e POSTGRES_DB=usersvc -e POSTGRES_USER=usersvc -e POSTGRES_PASSWORD=usersvc postgres:16
psql "postgresql://usersvc:usersvc@localhost:5432/usersvc" -f db/0001_identity.sql

# 2. 服务
dotnet run --project src/UserSvc.Api        # http://localhost:5080
```

API 文档在 <http://localhost:5080/scalar/v1>（仅 Development）。

开发期认证是占位实现，用两个头伪造身份：

```bash
curl http://localhost:5080/api/v1/user/profile \
  -H 'X-Dev-User-Id: 1' -H 'X-Dev-Session-Id: sid-1'
```

## 验证

```bash
dotnet build UserSvc.slnx      # 零警告（TreatWarningsAsErrors）
dotnet test  UserSvc.slnx      # 单元 + 架构守卫
```

## 当前进度

阶段 0 已完成：骨架、CI 门禁、架构守卫测试，外加一条打通的垂直切片（档案 + 设备会话）。

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 骨架 + CI 门禁 + 架构守卫 | ✅ |
| 1 | 用户档案 | 🟡 读写已通，缺注册与头像 |
| 2 | 验证码（Redis 限流、调通知服务） | ⬜ |
| 3 | 认证核心（OpenIddict、设备会话、令牌轮换） | ⬜ |
| 4 | 第三方身份（微信 / Firebase / LINE / Passkey） | ⬜ |
| 5 | 后台账号 + RBAC + 租户 | ⬜ |

## 还没接的东西

按蓝图应有、当前是占位或缺失的：

- **认证**：OpenIddict 签发 + JwtBearer 验签（现在是 `X-Dev-*` 头，仅开发）
- **撤销集**：Redis 适配器（现在是内存实现，非开发环境拒绝启动）
- **通知服务**：HTTP 客户端（现在抛 502）
- **Outbox 投递器**：事件已原子落表，还没有后台推送到 RabbitMQ
- **集成测试**：Testcontainers（包已在清单里，工程未建）
- **授权快照 / 网关注入**：待确定网关选型
