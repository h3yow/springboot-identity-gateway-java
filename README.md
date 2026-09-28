# Spring Boot Identity Gateway（本地身份认证与会话令牌闭环）

一个可在本地直接运行的最小身份网关：**两步登录（密码 + 一次性动态验证码）**、
**访问/刷新令牌签发与一次性轮换（含重放检测）**、**基于角色/权限/范围的统一访问控制**，
以及 **多端会话管理（多设备并存、会话清单、按会话精准下线、容量上限与最久未活跃淘汰）**。
不依赖数据库、短信/邮件渠道、真实第三方凭据或网络时间——用户目录为内存播种，
时间源可被测试完全控制。

## 1. 技术栈与运行要求

- Java 21+、Spring Boot 3.4.x、Spring MVC、JDK 内置 PBKDF2 / HMAC-SHA256
- 无外部中间件；构建：`mvn test`（含 47 个测试）

## 2. 演示账户（内存播种，仅用于本地）

| 用户名 | 密码 | 角色 | 权限 | 令牌范围 |
|---|---|---|---|---|
| `alice` | `password-alice` | `user` | `user:read` | `openid`, `reports:read` |
| `bob` | `password-bob` | `user` | `user:read` | `openid`（无 reports:read） |
| `admin` | `password-admin` | `admin`,`user` | `user:read`,`user:write` | `openid`,`reports:read` |

密码以 PBKDF2WithHmacSHA256（12 万轮、每盐 16 字节、32 字节哈希、常量时间比对）保存，
目录中不存在用户与密码错误返回**相同**结论，避免账户枚举。

## 3. 认证流程（两步登录）

```
第一步  POST /api/auth/login/password        { username, password }
        成功 -> 200 { status:"OTP_REQUIRED", otpForLocalDev:"143631" }
               服务端创建 OTP 挑战（仅存 SHA-256 哈希，默认 5 分钟有效）
        失败 -> 401 BAD_CREDENTIALS（失败计数 +1）
                423 ACCOUNT_LOCKED（达到阈值）

第二步  POST /api/auth/login/otp              { username, otp }
        成功 -> 200 { accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt }
        失败 -> 401 OTP_MISSING / OTP_EXPIRED / OTP_REUSED / OTP_MISMATCH
                423 ACCOUNT_LOCKED
```

关键规则：

- **OTP 原子一次性**：服务端“读取-判定-标记已消费”在 `OtpStore` 上以同步块串行。
  无论成功还是失败，挑战都会被消费；同一码二次提交得到 `OTP_REUSED`，与
  `OTP_EXPIRED`（`now > expiresAt`）、`OTP_MISMATCH`（哈希不一致）、
  `OTP_MISSING`（无未完成挑战）严格区分。
- **失败锁定**：同一用户名连续失败达到 `auth.max-failures`（默认 5）后锁定
  `auth.lock-millis`（默认 5 分钟，可配置）。锁定窗口内即使密码正确也返回
  `ACCOUNT_LOCKED`（HTTP 423）。窗口到期后下一次访问**自动清零恢复**，无需人工干预。
  第二步（OTP）的失败同样计入失败计数。
- **本地 OTP 回显**：默认 `auth.expose-otp-for-local-dev=true`，第一步响应直接带回
  OTP；接入真实渠道时置为 false，服务端仍不保存明文。

## 4. 令牌生命周期

令牌为不透明字符串：`base64url(payload).base64url(HMAC-SHA256(payload))`，
载荷为 JSON。刷新令牌在服务端只存其 SHA-256 哈希。

```
登录成功
  └─ 建立令牌族（family = 一次登录会话），签发 access + refresh
访问  受保护资源  -> 校验 签名/类型/过期/族是否撤销，通过后做 RBAC+范围判定
刷新  POST /api/auth/token/refresh { refreshToken }
  └─ 旧 refresh 原子置 used，同族签发新 access + refresh（Refresh Token Rotation）
撤销  POST /api/auth/token/revoke  { refreshToken } -> 撤销整族
```

**一次性刷新与重放检测（并发安全）**：

- 轮换以**令牌族为粒度加锁**（`TokenStore.withFamilyLock`），同一刷新令牌即便被
  16 个线程并发提交，也**恰好一次成功**。
- 任何对已使用刷新令牌的再次提交（串行重放或并发落败者）都视为重放：
  返回 `ROTATED` 并**立即撤销整个令牌族**——该会话下此前签发的全部 access/refresh
  令牌随即失效（再用得到 `REVOKED`），强制重新登录。

令牌被拒绝的原因全部可区分：

| reason | 含义 | 典型 HTTP |
|---|---|---|
| `MALFORMED` | 结构/编码不合法 | 400 |
| `BAD_SIGNATURE` | HMAC 校验失败（被篡改/换密钥） | 401 |
| `WRONG_TYPE` | 用 refresh 当 access 或反之 | 400 |
| `EXPIRED` | 超过 exp（access/refresh 分别判定），自然过期 | 401 |
| `ROTATED` | 刷新令牌已被使用，触发整族撤销 | 401 |
| `REVOKED` | 族已被用户主动撤销或被重放检测撤销 | 401 |
| `EVICTED` | 会话因同账号达到容量上限被“最久未活跃”策略淘汰 | 401 |
| `UNKNOWN` | 服务端无此刷新令牌记录 | 401 |

判定顺序：签名/类型 → 过期 → 会话状态（`REVOKED` / `EVICTED`）。时间一律取自可替换的
`Clock`，测试用 `MutableClock` 手动推进，过期结论 100% 稳定复现。

## 4.1 多端会话管理

一次登录 = 一个**令牌族（family）= 一个会话**；同一账号可在多台设备/客户端并行登录，
彼此完全隔离、互不影响。登录第二步可携带设备与客户端信息：

```
POST /api/auth/login/otp
{ "username":"alice", "otp":"143631",
  "deviceId":"phone-1", "deviceName":"alice 的手机", "clientId":"mobile-app" }
```

未携带时分别以 `UNKNOWN-DEVICE` / `UNKNOWN-CLIENT` 兜底。登录响应额外带回 `sessionId`
（即令牌族 id），供按会话精准下线使用。

### 会话清单

```
GET /api/sessions            （需携带某个有效访问令牌）
200 {
  "username":"alice", "count":2,
  "sessions":[
    { "sessionId":"...", "deviceId":"phone-1", "deviceName":"...", "clientId":"mobile-app",
      "createdAt":..., "lastActiveAt":..., "expiresAt":...,
      "roles":["user"], "permissions":["user:read"], "scopes":["openid","reports:read"] }
  ]
}
```

- **只能看到自己的会话**：属主身份取自访问令牌 claims，不接受调用方指定用户。
- **只显示有效会话**：已自然过期、已撤销、被淘汰的会话一律不出现。
- **能力概要与实际判定同源**：`roles/permissions/scopes` 取自该会话（令牌族）上的
  **登录时能力快照**，与该会话真正过 `AccessControlService` 校验用的能力是同一份数据。
- **续期不丢能力**：刷新令牌载荷内同样保存该快照，轮换后新访问令牌与清单概要都从快照继承，
  已授予的角色/权限/范围不会因续期而变少或消失。
- `lastActiveAt` 在每次受保护访问或成功续期时更新；`expiresAt = lastActiveAt + refresh TTL`，
  即会话随成功续期滑动，长期不活动则自然过期。

### 按会话精准下线

```
POST /api/sessions/{sessionId}/revoke      （需认证）
200 { "status":"REVOKED", "sessionId":"...", "changed":true }
```

- 仅撤销指定的那一个会话（令牌族），**其它设备会话照常可用**。
- 撤销后该会话的访问与续期都得到 `REVOKED`；并立即从会话清单消失。
- **重复撤销幂等**：对同一会话重复调用始终返回 `200 REVOKED`，第二次起 `changed=false`，
  不抛异常、结论稳定。
- 撤销在**族锁**内完成“属主校验 + 终态转换”，与续期/淘汰互斥。即便撤销与续期并发，
  也不会出现“撤销已生效、稍后又换出新可用凭证”的情况：族最终必为终态，终态后任何
  访问/续期都被拒绝。
- 目标会话不存在或**不属于当前用户**时统一返回 `404 SESSION_NOT_FOUND`
  （不区分“不存在”与“他人会话”，避免会话 id 枚举）。

### 容量上限与最久未活跃淘汰

- 上限由 `auth.max-sessions-per-user` 配置（默认 5；`0` 或负数表示不限制）。
- 同账号**有效会话数**（ACTIVE 且未过刷新有效期）达到上限后再次登录，会在**用户锁**内
  先淘汰 `lastActiveAt` 最小（最久未活动）的那一个，再建立新会话。
- 用户锁使并发登录被串行化：**有效会话数永远不会超过上限**；淘汰候选只可能是既有会话，
  刚建立的新会话绝不被误伤；淘汰只影响被选中的那一个，不连带同账号其它会话。
- 被淘汰会话的后续访问与续期得到独立原因 **`EVICTED`**，与用户主动撤销 `REVOKED`、
  自然过期 `EXPIRED`、重放 `ROTATED` 严格区分。

## 5. 访问控制规则

`BearerTokenInterceptor` 拦截所有 `/api/**`，判定统一走 `AccessControlService`：

1. **默认拒绝**：未标注 `@RequireAccess` 的入口直接 403 `DEFAULT_DENY`
   （见 `/api/protected/unannotated`）；登录/刷新/撤销是唯一的显式通道，
   逐方法标注 `@PublicEndpoint`。
2. **先认证**：无/无效/过期/撤销令牌 → 401 `UNAUTHENTICATED`。
3. **再角色与权限**：`@RequireAccess(roles=…, permissions=…, scopes=…)`；
   声明的每个维度按“命中其一即可”判定（OR），已声明的维度必须全部满足（AND）。
   角色与权限都不满足 → 403 `FORBIDDEN_NO_PERMISSION`。
4. **后范围**：角色/权限通过但令牌 scopes 不覆盖 → 403
   `FORBIDDEN_INSUFFICIENT_SCOPE`，与“无权限”明确区分。

演示入口：

| 入口 | 要求 | bob | alice | admin |
|---|---|---|---|---|
| `GET /api/protected/profile` | 仅认证 | 200 | 200 | 200 |
| `GET /api/protected/admin` | role admin 或 perm `user:write` | 403 NO_PERMISSION | 403 NO_PERMISSION | 200 |
| `GET /api/protected/reports` | scope `reports:read` | 403 INSUFFICIENT_SCOPE | 200 | 200 |
| `GET /api/protected/unannotated` | 未标注 | 403 DEFAULT_DENY | 403 DEFAULT_DENY | 403 DEFAULT_DENY |

每次判定都在日志中打印**输入**（用户名、要求与持有的 roles/permissions/scopes）
与**判定依据**（roleOk/permOk/scopeOk）；认证、OTP、锁定、轮换路径同样打印输入与结论。

## 6. 配置项（`src/main/resources/application.properties`）

| 属性 | 默认值 | 说明 |
|---|---|---|
| `auth.max-failures` | 5 | 触发锁定的连续失败次数 |
| `auth.lock-millis` | 300000 | 锁定时长，窗口到期自动恢复 |
| `auth.otp-ttl-millis` | 300000 | 动态验证码有效期 |
| `auth.access-token-ttl-millis` | 900000 | 访问令牌有效期（15 分钟） |
| `auth.refresh-token-ttl-millis` | 604800000 | 刷新令牌有效期（7 天） |
| `auth.token-signing-key` | 内置演示值 | Base64URL HMAC 密钥，生产必须覆盖 |
| `auth.expose-otp-for-local-dev` | true | 第一步响应是否回显 OTP |
| `auth.max-sessions-per-user` | 5 | 单账号同时有效会话上限，达到后淘汰最久未活跃者；0/负数表示不限制 |

### 6.1 对既有行为的兼容范围

- 两步登录、令牌一次性轮换、重放整族撤销、失败锁定、RBAC/范围判定的**既有接口与结论保持不变**。
- 登录第二步请求体中 `deviceId/deviceName/clientId` 为**可选**，不传时使用兜底值；
  既有不传这些字段的调用方无需改动。
- 登录响应在原有字段上**新增** `sessionId`（不删除、不改既有字段）。
- 新增端点 `GET /api/sessions` 与 `POST /api/sessions/{id}/revoke` 均需认证，
  与既有受保护入口共用同一套默认拒绝/认证/权限拦截。
- 令牌拒绝原因枚举**新增** `EVICTED`；既有原因值含义不变。
- 默认容量上限为 5，宽松到不影响既有“少量会话”用例；集成测试可通过属性覆盖。

## 7. 本地验证方法

### 7.1 自动化测试（推荐，不启动网络端口也能跑单元层）

```bash
mvn test                       # 全部 47 个测试
mvn test -Dtest=TokenServiceTest#concurrentRefreshExactlyOneSuccess
mvn test -Dtest=SessionManagementServiceTest
mvn test -Dtest=SessionHttpIntegrationTest
```

测试分层：

- `LoginServiceTest`（9）：凭据错误、OTP 过期/重放/错误/缺失、连续失败锁定、
  **锁定窗口到期自动恢复**（用 `MutableClock` 精确推进到到期前 1ms 与到期时刻）。
- `TokenServiceTest`（9）：签发校验、正常轮换、**16 线程并发刷新恰一次成功**、
  重放触发整族撤销且新老令牌全失效、access/refresh 过期、主动撤销、坏签名、
  错误类型、族隔离。
- `AccessControlServiceTest`（8）：三类拒绝原因边界、401 与 403 可区分。
- `SessionManagementServiceTest`（9）：多端并存与清单隔离、能力概要与实际判定一致、
  续期后能力不减少、按会话精准下线且重复撤销幂等、**撤销/续期并发 8 轮终态自洽**、
  容量上限“最久未活跃”淘汰、**10 线程并发登录不超上限且不误伤新会话**、
  被撤销/被淘汰会话的后续访问与续期结论、过期会话消失、跨用户撤销被拒。
- `AuthFlowIntegrationTest`（5）：MockMvc 全链路既有 HTTP 状态码与 reason 断言（回归保护）。
- `SessionHttpIntegrationTest`（6）：多端清单（认证/隔离/能力概要）、按会话下线端到端、
  撤销他人会话 404、容量淘汰返回 401 `EVICTED`、续期后能力与权限判定一致。
- `ApplicationTests`（1）：Spring 上下文装配冒烟。

所有时间相关用例均通过 `MutableClock` 手动推进，不依赖真实等待；全部可本地离线重复运行。

查看带输入与判定依据的日志：

```bash
mvn test -Dtest=LoginServiceTest 2>&1 | grep -E "OTP|锁定|判定"
```

### 7.2 手工 curl（真实 HTTP 闭环）

```bash
mvn spring-boot:run

# 1) 密码换 OTP（本地模式直接回显）
curl -s -X POST localhost:8080/api/auth/login/password \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-alice"}'

# 2) OTP 换令牌
curl -s -X POST localhost:8080/api/auth/login/otp \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","otp":"<上一步的 otpForLocalDev>"}'

# 3) 带访问令牌调用
curl -s localhost:8080/api/protected/profile -H "Authorization: Bearer <accessToken>"

# 4) 一次性轮换；再用同一个 refreshToken 重放 -> 401 ROTATED 且整族失效
curl -s -X POST localhost:8080/api/auth/token/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

# 5) 主动撤销会话
curl -s -X POST localhost:8080/api/auth/token/revoke \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

# 6) 多端：用不同 deviceId/clientId 再登录一台设备（OTP 步骤携带设备信息）
curl -s -X POST localhost:8080/api/auth/login/otp \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","otp":"<otp>","deviceId":"phone-1","deviceName":"alice 的手机","clientId":"mobile-app"}'

# 7) 查看自己当前所有有效会话（清单含设备、建立/活跃时间、能力概要）
curl -s localhost:8080/api/sessions -H "Authorization: Bearer <accessToken>"

# 8) 按会话精准下线某一台设备（不影响其它设备）；重复执行返回 changed=false
curl -s -X POST localhost:8080/api/sessions/<sessionId>/revoke \
  -H "Authorization: Bearer <accessToken>"
```

> 想观察容量淘汰：在 `application.properties` 设置 `auth.max-sessions-per-user=2`，
> 连续登录三台设备（中间让第二台访问一次受保护接口以更新活跃时间），第一台的刷新/访问
> 将返回 401 `EVICTED`，第二、三台照常，清单只剩两台。

## 8. 设计取舍说明

- **内存状态**：OTP 挑战、失败计数、令牌族/刷新记录均在内存，重启即清空，符合
  “本地可运行、无外部服务”的目标；生产化时把三个 Store/Counter 换成持久实现即可，
  接口语义（原子消费、族级锁、窗口判定）保持不变。
- **不回传明文**：OTP 与 refresh token 落库只存哈希；签名只证明令牌由本服务签发，
  是否有效仍以服务端状态（used / revoked / exp）为准。
- **会话即令牌族 + 能力快照**：设备/客户端、最近活跃时间、roles/permissions/scopes 都挂在
  令牌族上；清单概要与访问令牌、续期后的新令牌共用同一份登录快照，因此“看到的能力”与
  “实际校验用的能力”天然一致，续期不会缩水。
- **两层加锁保证自洽**：用户锁串行化同账号登录（容量检查 + 淘汰 + 新建原子完成），
  族锁串行化同一会话的续期/撤销/淘汰；固定加锁顺序“用户锁 → 族锁”，避免死锁。
  撤销/淘汰/重放均为只进不退的终态，保证竞争后结论唯一且可复现。
- **可解释失败**：登录、令牌、访问三个层面各有独立 reason 枚举，HTTP 状态码与
  reason 双重区分，日志同步打印输入与判定依据。主动撤销 `REVOKED`、容量淘汰 `EVICTED`、
  自然过期 `EXPIRED`、重放 `ROTATED` 彼此可区分。
