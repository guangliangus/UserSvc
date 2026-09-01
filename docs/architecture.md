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

## 占位实现要选安全的那一侧

未落地的依赖先定端口 + 写占位实现，让调用方逻辑一次写全。但占位实现宁可**失败**也不要
静默放行：

| 占位 | 行为 |
|---|---|
| `InMemorySessionRevocationStore` | 非 Development 环境**拒绝启动**——单副本内存集合在多副本下撤销不会传播 |
| `UnavailableNotificationClient` | 抛 502——假装发送成功会让用户永远等不到验证码却看不到错误 |
| `DevAuthenticationHandler` | 只在 Development 注册；生产缺认证方案会启动失败 |

## 数据库

`db/README.md`。要点：**应用永不改库**，DDL 手动先行，脚本幂等。
