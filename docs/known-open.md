# 已知未决项

这里只放**有意留着不做**的事。每一条写三样东西：**开着的是什么**、**代价是什么**、
**关掉它需要什么**。目的是让下一个人**接手**，而不是重新发现一遍——过去七个 wave 里，
下面这几条平均每条被独立"发现"过两次以上。

不属于这里的：bug（去修）、TODO（去做）、想法（去蓝图）。
**一条进来的前提是有人已经判断过"现在不做"，并且知道为什么。**

约束本身在 [`architecture.md`](architecture.md)。本文只讲缺口。

核实日期：**2026-09-02**，仓库 HEAD `c6914ce`，活库 `lion_user`。
下面每一条都对着代码和活库重新查过；有两条的原始描述查出来是错的，改写在各条里。

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

## 2 · 后台密码只认 Argon2id，而活库里 17 个后台账号全是 bcrypt

**原始描述是「`iam.backend_users` 没有密码算法列」。查下来这个框法不对，而且它盖住了
一个更硬的问题。** 分两半说。

**没有算法列这半，可以关。** 今天的签入代码**不做算法嗅探，也不做分派**——它只有一种算法。
`PasswordHasher.Verify` 要求 PHC 串的第一段等于 `argon2id`，别的一律 `false`；
`BackOfficeSignInAppService` 里那个 `!stored.StartsWith("$argon2id$")` 只是**一条 Error 日志**，
不是分支。算法列本来只买一件事——"哪些行还需要重新 hash"——而 PHC 串自己就带着算法名，
`WHERE password_hash NOT LIKE '$argon2id$%'` 给的是同一个答案，同样的代价。所以这一列不欠。
（C 端的 `identity.users.password_algo` 确实存在，注释写着 `BCRYPT | ARGON2ID`；
那是 C 端当初预留的，`PasswordHasher` 从没长出 bcrypt 分支。对 C 端无害：
活库 `uam.users` 是 **0 行**，实测，所以真的没有 bcrypt 消费者哈希要验。）

**真正开着的是另一半：后台平面不是 0 行。** 活库读数（2026-09-02）：

| 表 | 行数 | 有密码 | bcrypt | argon2id |
|---|---|---|---|---|
| `uam.backend_users`（被替换的 Go 服务） | 17 | 17 | **17**（全是 `$2a$10$`） | 0 |
| `iam.backend_users`（本服务） | 11 | 3 | 0 | 3 |

`uam.backend_users` 同样没有算法列。所以切换当天，那 17 个运营账号的密码门**全部打不开**：
`Verify` 返回 `false`，响应是 401 `INVALID_CREDENTIALS`，**和输错密码完全无法区分**，
唯一的信号是每次尝试一条 Error 日志说这一行不是 Argon2id PHC 串。
实测（把活库里一条真的 `$2a$10$...` 喂给 `PasswordHasher.Verify`）：`false`；
同一个 hasher 的 Argon2id 串往返：`true`。所以那个 `false` 是关于算法的，不是探针写错了。

**代价是什么。** 现在什么都不花——本服务的 `iam.backend_users` 里没有 bcrypt 行。
代价全部在**切换那一刻**兑现，而且它长得像"新系统的密码登录坏了"，不像一次数据迁移遗漏。

**关掉它需要什么。** 两条路，选一条并写下来：

- **加一个 bcrypt 验证分支 + 登录时重新 hash。** 要引一个 bcrypt 依赖，
  `Verify` 变成按前缀分派（`$2a$`/`$2b$` → bcrypt，`$argon2id$` → 现在这条），
  验过之后就地用 Argon2id 重写并更新那一行。前缀嗅探在这里是**健全的**，
  因为 PHC 和 bcrypt 的串都自带算法名——缺的从来不是那一列，是那个分支。
- **切换步骤里强制这 17 个账号改密。** 一次都不用碰验证代码，
  代价是切换当天要走完 17 次找回流程——而后台自助改密**今天还走不通**（见第 6 条）。

决策归属：拥有切换计划的人。

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

**这一条多了个第三个预言机，需要补进那张表。**
`BackOfficeResetTargetGate` 已经落地了（`architecture.md` 的表里还写着"一旦落地……届时本表要补一行"），
它用 `UNREGISTERED` / `ACCOUNT_DISABLED` 暴露**后台**身份的同类事实，
而且它自己的类注释明确写着"本 gate 是一个账号存在性预言机，并且我们知道"。
它今天还构不成实际泄露，只因为它走不通（第 6 条）——那个门一通，这一行就要补上去。

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

## 6 · 后台自助改密只落了一半，而两处注释说它是通的

**这一条是 wave 8 查出来的，不是继承来的。**

**开着的是什么。** 后台自助改密的零件都写好了——`BackOfficeResetTargetGate`、
`BackOfficeAccountAppService.ResetPasswordAsync`、`BackOfficePasswordResetRequest`
和它的 validator——但这条流程**端到端走不通**，两头都断：

- **发码这头**：`VerificationAppService.EnsureTargetSuitsPurposeAsync` 对
  `backoffice_reset_password` 仍然抛 `501 NOT_IMPLEMENTED`。
  实测（跑起来的服务，2026-09-02）：
  `POST /api/v1/verification/send` 带 `purpose=backoffice_reset_password` →
  `501 NOT_IMPLEMENTED`，"Back-office password reset is not available yet."
  所以调用方永远拿不到 `ResetPasswordAsync` 需要的那张 verification ticket。
- **提交这头**：`ResetPasswordAsync` **没有任何 controller 路由**。
  实测：服务的 OpenAPI 文档 61 个路径 / 71 个操作里，唯一带 reset 的是
  `POST /api/v1/back-office/tenants/{tenantType}/{tenantCode}/members/{userId}/reset-password`——
  那是**管理员给别人重置**，不是自助。

**真正的代价不是缺功能，是两处注释在说假话。** 缺功能是清楚的、可见的；
注释把它盖住了：

- `BackOfficeResetTargetGate` 的类注释写着「**它故意跑两次**……验证模块在发码前跑一次，
  所以没人会为一个反正也重置不了的邮箱收到验证码；本 feature 在票据被花掉时再跑一次」。
  **实际上它只跑一次**——全仓库只有 `BackOfficeAccountAppService` 一个调用点，
  验证模块里没有任何地方碰它。于是它"为什么是一个类而不是一个私有方法"的理由也不成立。
- `ResetPasswordAsync` 里写着「**发码那步跑过的同一个 gate**，这里重复一遍，
  因为账号可能在邮件发出到票据被花之间被停用」。发码那步答的是 501。

一个读者（或下一个 agent）会据此相信"发码那头已经在 gate 了，只差接线"，
从而不去查发码那头——这正是本文档存在的理由的反面。

**关掉它需要什么。** 三件事，其中第三件不做的话前两件是在开一个新的预言机：

1. `EnsureTargetSuitsPurposeAsync` 的 `backoffice_reset_password` 分支改成调
   `BackOfficeResetTargetGate.ResolveAsync`，替掉那个 501。
2. 给 `ResetPasswordAsync` 加一个匿名路由。
3. **同时**把 `architecture.md` 预言机表里 `backoffice_reset_password` 那一行补齐：
   通了之后它就用 `UNREGISTERED` / `ACCOUNT_DISABLED` 对匿名调用方暴露后台身份是否存在
   （见第 3 条）。gate 自己的注释已经承认了这一点，表里还没有。

**在那之前，至少要把那两处注释改成事实。** 一条"这里还没接上"的注释比一条描述了
不存在的接线的注释便宜得多，而且它正好是第 6 条这类东西被发现的方式。

---

## 怎么维护这份清单

- 关掉一条就**删掉它**，别留一条"已完成"——留着会让清单看起来比实际长，
  下一个人读到第三条"已完成"就不再读了。第 5 条这一轮就是这么关的：
  它的处置和证据写在里面，等有人读过一遍，整节可以删。
- 新增一条要能回答那三个问题。答不上"关掉它需要什么"的，是 TODO，不是未决项。
- **每一条都要标核实日期。** 上面六条里有两条（第 2、5 条）的原始描述在核实时被推翻，
  而它们都被原样传了好几个 wave。没核实日期的条目下一个人只能重新查一遍——
  那就回到了这份文档要解决的问题。
