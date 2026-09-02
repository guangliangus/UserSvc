# 已知未决项

这里只放**有意留着不做**的事。每一条写三样东西：**开着的是什么**、**代价是什么**、
**关掉它需要什么**。目的是让下一个人**接手**，而不是重新发现一遍——过去七个 wave 里，
下面这几条平均每条被独立"发现"过两次以上。

不属于这里的：bug（去修）、TODO（去做）、想法（去蓝图）。
**一条进来的前提是有人已经判断过"现在不做"，并且知道为什么。**

约束本身在 [`architecture.md`](architecture.md)。本文只讲缺口。

核实日期：**2026-09-02**（第 1、3、4、5 条），**2026-09-03**（第 6、7、8 条），
仓库 HEAD `903d10a`，活库 `lion_user`。
每一条都对着代码和活库查过，不是继承来的描述。wave 9 关掉了原第 2 条（后台密码只认
Argon2id）并重写了第 6 条；它们的代价分别落在新的第 7、8 条上。

---

## 1 · LionTravel 一次性密码上游的线上契约是**假设**的

**开着的是什么。** `LionTravelStaffDirectory` 的每一个线上细节都来自一份文字描述，
不是上游自己的契约文档：三个路径（`v2/token/generator`、`api/V2/OTPLogin`、
`api/V2/Staff/StaffProfile`）、请求体字段名（`Stfn` / `Pswd`）、响应信封的大小写混用
（PascalCase 信封 + lowerCamel 结果 + `rCode`/`rDesc`）、checksum 的配方，
以及那个 `Authorization` 头**自带 `"basic "` 前缀、我们不再加一层**的约定。

**代价是什么。** 单测把每一条假设都断言住了，所以对不上的时候失败信息会指名字段，
而不是笼统的"登录不好用"——这是今天唯一的保护。但**第一次真实调用才是验证**。
另外两件事跟着这个假设一起没被验证过：checksum 只编码 UTC 的 `HHmmss`，
所以宿主时钟漂几秒就会每个请求都被拒（NTP 是这个 adapter 的部署要求，不是可选项）；
以及三个 base address 是三个不同的主机，所以这个 client **故意不设 `BaseAddress`**。

**关掉它需要什么。** 拿到上游的接口文档，或者对着测试环境跑一次真调用，然后把
`LionTravelStaffDirectory` 类注释里那段"每个细节都是假设"改写成"已核对，见 xxx"。
在那之前不要把这段注释删掉——它是读者判断该信多少的唯一依据。

---

## 3 · 发码接口的两个「是否已注册」预言机

**开着的是什么。** `reset_password` 答 `400 UNREGISTERED`，`bind` 答
`409 IDENTITY_ALREADY_BOUND`，两个路由都是 `[AllowAnonymous]`，
于是**任意匿名调用方**都能拿错误码问出"这个手机号/邮箱注册过没有"。
这是从 Go 服务原样移植的**客户端契约**，移动端现在就分支在这两个错误码上。

实测（2026-09-02，跑起来的服务）：
`POST /api/v1/verification/send` 带 `purpose=reset_password` 和一个没注册的地址 →
`400 UNREGISTERED`，`detail` 是 "That email address or phone number is not registered."

**代价是什么。** 完整的一张表（泄露什么、对谁、在哪些 purpose 上，
以及为什么"只在这个接口关"等于什么都没买到）在
[`architecture.md` 的「发码接口的两个『是否已注册』枚举预言机」](architecture.md)。
不在这里重复；那一节比这里详细，而且它记着今天真正约束这次抓取的东西是
**风控排在前置校验之前**跑。

**关掉它需要什么。** 一次**跨接口、跨所有生成客户端**的协同契约变更：
所有接收标识符的流程统一成一句无差别应答，连 OpenAPI schema 和各端分支逻辑一起改。
决策归属：拥有客户端契约的人。**在此之前保留现状是有意的，别在移植/评审中单方面改动。**

**第三个预言机曾经在这里，wave 9 把它关了，不是记下来了。**
`backoffice_reset_password` 接通时没有沿用 `UNREGISTERED` / `ACCOUNT_DISABLED`，
而是改成一句无差别应答；理由（这条 purpose 没有已有客户端分支、它问的是运营目录、
以及同平面的密码门已经为同一个预言机付过钱）与残留的两条侧信道都在
[`architecture.md` 那一节](architecture.md)，缺口部分见本文第 6 条。
**所以本条只剩 C 端那两个**，它们仍然是客户端契约，仍然不要单方面改。

---

## 4 · `ITenantMasterDataDirectory` 是最后一个拒绝式占位，供应商挂载因此走不通

**开着的是什么。** 核实过：`UnavailableTenantMasterDataDirectory` 是
`DependencyInjection` 里唯一还注册着的 `Unavailable*` 占位（`UnavailableNotificationClient`
早就删了；`IStaffDirectory`、`ICaptchaVerifier`、`IObjectStorage` 都是真 adapter，
缺的只是凭据）。真实现要读的是 PIM 服务持有的公司/供应商主数据登记表——
本服务一行都不存，`iam.tenant_members.tenant_code` 是一个**故意没有外键**的逻辑引用，
正因为被引用的行在别人家。

**它答 `null`，而 `null` 在这个 port 的词汇里是"没问到"，不是"没有"。** 一个值，两种正确行为：

| 调用方 | 收到 null 时 | 为什么 |
|---|---|---|
| 租户上下文的**读** | fall-open | 这个门是拦"已停用的租户"，不是授权边界（授权边界是 member 行 + 权限码）；主数据一挂就把全平台锁在所有租户外面，代价远大于收益 |
| 供应商**挂载写** | 502，什么都不写 | 两个 code 背后都没有外键，falling open 等于把数据范围授给一个没人确认存在过的公司 |

**代价是什么。** 挂载路径**在今天任何部署上都不可能成功**，所以它端到端没有覆盖，
也没有任何真实调用验证过。方向本身是对的（spec 12 §3.1.4 步骤 1 要求它拒），
但"拒"这个分支是唯一被走过的分支——三个 verdict 里 `Usable` 和 `NotUsable`
两条从来没有被真数据触发过。

**关掉它需要什么。** 一个 PIM adapter：给 `ValidateAsync` 一个真实现，
把上游答案映射成三个 `Verdicts`（缺失和"回声说不存在"要映射成同一个 `Unknown`——
port 明确要求调用方无法区分这两者）。有了它，挂载路径才第一次能跑通，
`TenantMasterDataEntry.Name` 的本地化名字也才第一次有值（现在恒空，前端渲染 code）。

---

## 5 · realm 回填的标注——**这一条查下来是可以关的，而且已经复核过了**

**原始描述是「realm 回填的标注事后无法复核」。今天不成立：能复核，我复核了，全对。**

`db/0001_identity.sql` 的回填按证据逐行标注（会话指向的 OpenIddict authorization
是否申请了 `backoffice` scope）。那份证据**还在**，所以复核就是一句 join。
活库实测（2026-09-02）：

| realm | 会话数 | authorization 仍在 | 证据已丢 | authorization 说是后台 |
|---|---|---|---|---|
| `BACKOFFICE` | 9 | 9 | 0 | **9** |
| `CONSUMER` | 16 | 16 | 0 | **0** |

25 行全部对得上，一行不差。另外 `revoked_by = 'ADMIN'` 是 **0 行**，
也就是"证据已丢就直接撤销"那条分支在这个库上从没触发过——
所以没有任何一行是被回填顺手撤掉的。

**还开着的只有一件事：这个复核有窗口期。** 它依赖 authorization 行活着，而
`OpenIddictPruningService` 默认每小时跑一次、删 **45 天**以前的 token 和 authorization。
过了保留期，对应的会话就再也无法复核了——不是标错了，是证据被正常清掉了。

**所以这一条的处置是：现在就关，并把复核查询留下来**，谁将来怀疑标注对不对，重跑一次即可：

```sql
SELECT s.realm,
       count(*)                                                AS sessions,
       count(*) FILTER (WHERE a.id IS NULL)                    AS evidence_gone,
       count(*) FILTER (WHERE a.scopes LIKE '%"backoffice"%')  AS authz_says_backoffice
  FROM identity.user_sessions s
  LEFT JOIN openiddict.openiddict_authorizations a ON a.id::text = s.authorization_id
 GROUP BY 1;
```

判读方法：`BACKOFFICE` 行的 `authz_says_backoffice` 应当等于 `sessions`，
`CONSUMER` 行的应当等于 0。`evidence_gone` 不为 0 的部分是过了保留期的行，
它们无法判读，也不该被当成标错。

---

## 6 · 后台自助改密通了，剩下两条侧信道是有意留着的

**第 6 条原来的内容（两头都断、两处注释说假话）在 wave 9 关掉了**，处置写在
[`architecture.md` 的「`backoffice_reset_password` 为什么反过来关掉了」](architecture.md)：
发码分支改成调 `BackOfficeResetTargetGate.EvaluateAsync`，提交端有了
`POST /api/v1/auth/back-office/password-reset`（匿名、204、per-source 预算），
两处假注释改成了事实。端到端实测（2026-09-02，本机服务 + 桩通知服务 + 活库）：
发码 200 → verify 200 拿到 ticket → 提交 204 → `iam.backend_users` 的 hash 变成真的 Argon2id
（`$argon2id$v=19$m=19456,t=2,p=1`）、`token_version` 0→1、审计表写下
`SELF_PASSWORD_RESET`（带 ip 与 request_id）；用新密码登录 200、旧密码 401；
同一张 ticket 重放 400 `VERIFICATION_FAILED`。（探针账号与其产生的行事后已删除，库回到 11 行 / 3 个有密码。）

**还开着的是什么。** 无差别应答只关掉了**错误码**这一层，两条侧信道还在，都实测过：
发码耗时（静默拒绝 ~5–6ms vs 合格 ~10–17ms），以及通知服务停机时合格目标答
`502 SEND_FAILED`、不合格目标答 200——停机窗口里预言机完整回来。

**代价是什么。** 抓取一次企业邮箱清单需要多次采样（时间）或者恰好赶上一次通知服务停机，
而 per-IP 发码预算与风控的每设备计数都排在查库之前。所以代价是「有耐心且有条件的攻击者仍能
问出后台账号是否存在」，不是「任何人一个请求就能问出来」。

**关掉它需要什么。** 时间那条：让不合格目标也付同样的代价（写一行没人能用的 code 行、
或者假装调一次通知服务），两者都是拿垃圾写入换一条侧信道，得有人认这笔账。停机那条：
把 `502 SEND_FAILED` 也吞成 200——**不建议**，理由写在 architecture.md 那一节里
（对真正在改密码的人，「发不出去」是他唯一需要的信息）。
决策归属：拥有客户端契约的人，和上面第 3 条是同一次决定。

---

## 7 · bcrypt 分支重新打开了一个**会自己关掉**的计时预言机

**这一条是 wave 9 加进来的，是关掉原第 2 条的代价，不是遗漏。** 核实日期：**2026-09-03**。

**开着的是什么。** 密码门现在按存储串自己的前缀分派：`$2a$`/`$2b$`/`$2y$` 走 bcrypt，
`$argon2id$` 走原来那条。bcrypt cost 10 与 Argon2id `m=19456,t=2,p=1` **不是同一个价钱**，
所以「一个还没迁移的行」和「其他一切」在时钟上可以分开。实测两遍，两遍一致。

单独测（n=40，中位数）：Argon2id **36.9 ms**，bcrypt cost 10 **49.3 ms**。
跑起来的服务上走真 HTTP（每条路径 30 个交错样本，先打 50 次热身，中位数）：

| 路径 | 中位数 |
|---|---|
| 未知邮箱 | 43.0 ms |
| 有账号但没有本地密码 | 45.6 ms |
| 密码错，Argon2id 行 | 45.4 ms |
| 密码错，**bcrypt 行** | **57.6 ms** |

wave 7 等价化的那三条**仍然等价**——彼此相差 2.6 ms（wave 7 当初关掉的那个差是 48.7 ms）。
第四条比它们高 12.5 ms，1.27 倍，而且样本区间不重叠（bcrypt 56.2–59.0，Argon2id 43.5–51.2）。

**独立复测过（另一个 agent，另一个时刻，n=40）**：41.5 / 45.0 / 47.0 与 57.0 ms，
等价三条相差 5.5 ms，比值**同样是 1.27 倍**，区间同样不重叠。
隔离测同样对得上：Argon2id 35.3ms、bcrypt cost 10 49.0ms、cost 12 196.1ms。
也就是说这组数字**不是一次测量的运气**，比值是可复现的那一部分。

**代价是什么。** 「未知邮箱」正是被等价化的三条之一，所以一个还没迁移的行比它贵，
就等于**「这个地址存在」重新可以从时钟上读出来**——不只是「这个地址还没迁移」。
这一条必须这么说，不能圆成「只泄露迁移状态」。

三件事框住它，但没有一件是修法：

- 差值是**四分之一**次验证，而不是 wave 7 那个十四倍；
- 集合最多就是 Go 服务留下的 **17 行**；
- 每一行在它主人第一次成功登录时**永久离开这个集合**，因为那次登录就把它重写了。
  也就是说它**会自己关掉**——这正是它比「切换当天 17 个运营全登不进来」更划算的原因。

还有一个部署当天才看得见的细节：**新进程里 bcrypt 那条路径最初几次是 95–100 ms（约 2.0 倍），
不是 57.6 ms**——分层编译还没提升一条只被少数请求走过的代码。也就是说差值最大的时刻
恰好是集合最大的时刻：刚上线那几分钟。

**关掉它需要什么。** 三条路：

1. **等这 17 行迁移完**：`SELECT count(*) FROM iam.backend_users WHERE password_hash NOT LIKE '$argon2id$%'`
   归零之后，把 bcrypt 依赖和整个分支一起删掉。这是自然终点，中间不需要写任何代码。
2. **切换前用别的办法迁移这 17 行**——需要明文，而没人有。
3. **填充延迟**——`BackOfficePasswordTiming` 的类注释解释了为什么不选它：填充要长于负载下
   最慢的一次真验证，那是个没人知道的数字，而且它会让每一次密码错都变慢。

守住这条界限的是 `ALegacyRowsRefusalStaysWithinOneVerifyOfTheEqualisedPaths`：比值超过 2.5
构建失败。它防的不是这个分支，是**有人为了让注册便宜一点去调低 Argon2id 参数**——
把 memory 减半会把比值推到 2.9，实测，测试确实红了。

决策归属：无须决策，等它自己关。想提前关的走本条上面那三条路里的第 1 条（等它迁移完）。

---

## 8 · `BackOfficeAccountAppService` 的另外三个用例仍然没有路由

**开着的是什么。** 这个 app service 写好了四个用例，wave 9 只给其中一个接了路由。
实测（2026-09-03，跑起来的服务的 OpenAPI 文档）缺的是：

| spec 07 §4 的路由 | 对应方法 | 现状 |
|---|---|---|
| `POST /api/v1/auth/back-office/register` | `RegisterAsync` | 无路由 |
| `GET /api/v1/back-office/users` | `ListAsync` | 无路由 |
| `GET /api/v1/back-office/user/options` | `ListOptionsAsync` | 无路由 |
| `GET /api/v1/back-office/users/{id}`（detail） | 方法本身也没有 | 未实现 |

`Program.cs` 一直注册着 `BackOfficeAccountAppService`，所以容器里有它、单测覆盖着它，
只是没有任何 HTTP 入口——在 wave 9 之前它**一个路由都没有**，原第 6 条查的是其中一个。

**代价是什么。** 后台注册与运营目录（列表、people picker）在任何部署上都调不到，
而 `BackOfficeUserResponse` 的类注释已经在解释「为什么它先不带角色」——读起来像是已经上线的接口。
这与原第 6 条是同一个形状：零件齐、注释齐、没有门。

**关掉它需要什么。** 一个 controller，按 spec 07 §4 接三个路由：register 匿名（域名门在 service 里）、
两个目录读走 `uam.member.read` 与 `BackOfficePolicies.BackOffice`，`ListOptionsAsync` 按 spec
故意不要权限码（可见性过滤是它唯一的机密性控制，写在方法注释里）。detail 要先补 app service 方法。

---

## 怎么维护这份清单

- 关掉一条就**删掉它**，别留一条"已完成"——留着会让清单看起来比实际长，
  下一个人读到第三条"已完成"就不再读了。第 5 条这一轮就是这么关的：
  它的处置和证据写在里面，等有人读过一遍，整节可以删。
- 新增一条要能回答那三个问题。答不上"关掉它需要什么"的，是 TODO，不是未决项。
- **每一条都要标核实日期。** 过去有两条（当时的第 2、5 条）的原始描述在核实时被推翻，
  而它们都被原样传了好几个 wave。没核实日期的条目下一个人只能重新查一遍——
  那就回到了这份文档要解决的问题。
- **关掉一条留下的代价，要作为新的一条写下来，并且不要复用被删掉的编号。**
  第 7、8 条就是这么来的：原第 2 条关掉后留下一个计时残差，原第 6 条接通后暴露出
  同一个 app service 还有三个用例没有路由。沿用旧编号会让所有交叉引用错位。
