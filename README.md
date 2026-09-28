# Spring Boot Identity Gateway（本地身份认证、多端会话与访问控制闭环）

一个可在本地直接运行的最小身份网关：**两步登录（密码 + 一次性动态验证码）**、
**访问/刷新令牌签发与一次性轮换（含重放检测）**、**基于角色/权限/范围的统一访问控制**、
**多端会话管理（会话清单、按会话精准下线、账号级容量上限与 LRU 淘汰）**。
不依赖数据库、短信/邮件渠道、真实第三方凭据或网络时间——用户目录为内存播种，
时间源可被测试完全控制。

## 1. 技术栈与运行要求

- Java 21+、Spring Boot 3.4.x、Spring MVC、JDK 内置 PBKDF2 / HMAC-SHA256
- 无外部中间件；构建：`mvn test`（含 53 个测试）

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
| `EXPIRED` | 超过 exp（access/refresh 分别判定） | 401 |
| `ROTATED` | 刷新令牌已被使用，触发整族撤销 | 401 |
| `REVOKED` | 族已被重放检测或用户主动撤销 | 401 |
| `EVICTED` | 会话因账号达到并发上限、按最久未活跃被淘汰 | 401 |
| `UNKNOWN` | 服务端无此刷新令牌记录 | 401 |

判定顺序：签名/类型 → 过期 → 会话状态（EVICTED / REVOKED）。时间一律取自可替换的 `Clock`，
测试用 `MutableClock` 手动推进，过期结论 100% 稳定复现。

> 续期能力保持：登录时授予的 roles/permissions/scopes 以**服务端会话快照**为准保存于令牌族；
> 每次刷新都据此重新签发（刷新令牌载荷也携带同一快照）。因此续期后已授予能力不会凭空减少或消失，
> 会话清单展示的能力概要与实际权限判定、续期后新令牌承载的能力三者同源一致。

## 5. 多端会话管理

“一次登录 = 一个令牌族 = 一个会话”。同一账号可在多台设备/客户端同时登录，彼此隔离互不影响；
会话状态、客户端画像、能力快照与最近活跃时间都保存在服务端令牌族上。

### 5.1 登录时声明客户端画像（可选）

第二步 OTP 请求体可选携带设备/客户端字段（缺省为 unknown，不影响既有调用）：

```json
{ "username": "alice", "otp": "143631",
  "deviceType": "phone", "deviceName": "iPhone 15", "clientId": "ios-app" }
```

### 5.2 查看本人有效会话

```
GET /api/sessions        （需登录，携带 access 令牌）
```

返回当前仍有效的会话数组，每项含：`sessionId`、`deviceType/deviceName/clientId`、
`createdAt`（建立时间）、`lastActiveAt`（最近一次访问/续期时间）、`expiresAt`（会话到期时间）、
以及能力概要 `roles/permissions/scopes`。规则：

- **只能看到自己的会话**：服务端按令牌属主严格隔离，他人会话不可见、不可操作。
- 已**撤销**、已**淘汰**、已**自然过期**的会话一律不再出现。
- 能力概要直接取自服务端会话快照，与该会话过权限校验时使用的能力一致。

### 5.3 按会话精准下线

```
POST /api/sessions/{sessionId}/revoke     （需登录）
-> 200 { "status":"REVOKED", "sessionId":"...", "state":"REVOKED" }
```

- 只终止被选中的那一个会话，该会话随后的**访问与续期都得到 `REVOKED`（401）**，其它设备照常可用。
- **幂等**：对同一会话重复撤销得到一致结论（始终 200、`state=REVOKED`），不抛异常、不抖动。
- 终态“先到先得”：已被容量淘汰的会话再调撤销，返回并保持 `EVICTED`，不会被改写成 REVOKED。
- 越权操作他人会话 → `403 SESSION_NOT_OWNED`；会话不存在/已从存储消失 → `404 SESSION_NOT_FOUND`。
- 旧的 `POST /api/auth/token/revoke { refreshToken }` 保持可用（撤销该刷新令牌所属整族）。

### 5.4 撤销与续期竞争自洽

撤销与刷新都在**族锁**内串行判定。若撤销先持锁，随后到达的续期看到 REVOKED 被拒，不会再换出新凭证；
若续期先一步成功，其刚换出的新 access/refresh 也会因紧接着的撤销立即失效（REVOKED）。
无论两个请求怎样交错，最终族一定处于 REVOKED，且不会出现“撤销已生效、过一会儿又换出新凭证继续能用”。

### 5.5 容量上限与 LRU 淘汰

- 上限由 `auth.max-sessions-per-user` 配置（默认 5，**≤0 表示不限制**，保留旧行为）。
- 同一账号达到上限后再次登录：在该账号的**用户锁**内做“容量判定 + 淘汰 + 建新会话”，
  仅淘汰**当前仍有效、`lastActiveAt` 最早**的那一个旧会话，然后正常建立新会话。
- 被淘汰会话的后续访问/续期都得到 **`EVICTED`（401）**，与用户主动撤销（REVOKED）、
  自然过期（EXPIRED）明确区分。
- 淘汰只影响被选中的一个会话，不连带同账号其它会话；多个登录并发时也绝不超过上限，
  且新建立的会话不会被误伤（淘汰候选只取建立之前已存在的旧会话）。
- 每次成功访问会更新 `lastActiveAt`（原子写，不与族锁竞争），续期成功会滑动
  `lastActiveAt` 与会话 `expiresAt`。

会话操作相关的拒绝结论：

| 场景 | reason | HTTP |
|---|---|---|
| 撤销/操作他人会话 | `SESSION_NOT_OWNED` | 403 |
| 指定会话不存在或已消失 | `SESSION_NOT_FOUND` | 404 |
| 被淘汰会话再访问/续期 | `EVICTED` | 401 |
| 主动撤销会话再访问/续期 | `REVOKED` | 401 |
| 会话/刷新令牌自然过期 | `EXPIRED` | 401 |

## 6. 访问控制规则

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

## 7. 配置项（`src/main/resources/application.properties`）

| 属性 | 默认值 | 说明 |
|---|---|---|
| `auth.max-failures` | 5 | 触发锁定的连续失败次数 |
| `auth.lock-millis` | 300000 | 锁定时长，窗口到期自动恢复 |
| `auth.otp-ttl-millis` | 300000 | 动态验证码有效期 |
| `auth.access-token-ttl-millis` | 900000 | 访问令牌有效期（15 分钟） |
| `auth.refresh-token-ttl-millis` | 604800000 | 刷新令牌有效期（7 天），续期后滑动 |
| `auth.max-sessions-per-user` | 5 | 单账号同时有效会话上限，超限登录淘汰最久未活跃会话；≤0 表示不限制 |
| `auth.token-signing-key` | 内置演示值 | Base64URL HMAC 密钥，生产必须覆盖 |
| `auth.expose-otp-for-local-dev` | true | 第一步响应是否回显 OTP |

## 8. 本地验证方法

### 8.1 自动化测试（推荐，不启动网络端口也能跑单元层）

```bash
mvn test                       # 全部 53 个测试
mvn test -Dtest=TokenServiceTest#concurrentRefreshExactlyOneSuccess
mvn test -Dtest=MultiSessionTokenServiceTest#revokeAndRotateRaceConsistent
```

测试分层：

- `LoginServiceTest`（9）：凭据错误、OTP 过期/重放/错误/缺失、连续失败锁定、
  **锁定窗口到期自动恢复**（用 `MutableClock` 精确推进到到期前 1ms 与到期时刻）。
- `TokenServiceTest`（9）：签发校验、正常轮换、**16 线程并发刷新恰一次成功**、
  重放触发整族撤销且新老令牌全失效、access/refresh 过期、主动撤销、坏签名、
  错误类型、族隔离。
- `SessionServiceTest`（9）：多端并存清单、属主隔离、撤销/淘汰/过期不出现、
  能力概要取自会话快照、精准撤销只影响目标会话、重复撤销幂等、越权 403、终态先到先得。
- `MultiSessionTokenServiceTest`（7）：容量上限与 LRU 选择、被淘汰会话访问/续期得
  EVICTED 且与 REVOKED/EXPIRED 区分、淘汰不连带、**50 轮撤销/续期竞争自洽**、
  **12 线程并发登录不超上限且新会话不被误伤**、续期后角色/权限/范围不丢失。
- `AccessControlServiceTest`（8）：三类拒绝原因边界、401 与 403 可区分。
- `AuthFlowIntegrationTest`（5）：MockMvc 全链路 HTTP 状态码与 reason 断言，
  时钟固定为 `MutableClock`，每个用例前清空 OTP/失败计数/令牌存储保证隔离。
- `MultiSessionIntegrationTest`（5）：多端清单与属主隔离、按会话精准下线与重复撤销、
  越权撤销 403、容量淘汰 LRU 且被淘汰者 401 EVICTED、续期后能力概要与 admin/reports
  实际权限判定一致。

查看带输入与判定依据的日志：

```bash
mvn test -Dtest=LoginServiceTest 2>&1 | grep -E "OTP|锁定|判定"
```

### 8.2 手工 curl（真实 HTTP 闭环）

```bash
mvn spring-boot:run

# 1) 密码换 OTP（本地模式直接回显）
curl -s -X POST localhost:8080/api/auth/login/password \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password-alice"}'

# 2) OTP 换令牌（可选携带设备/客户端画像，用于多端清单区分）
curl -s -X POST localhost:8080/api/auth/login/otp \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","otp":"<上一步的 otpForLocalDev>",
       "deviceType":"phone","deviceName":"iPhone 15","clientId":"ios-app"}'

# 3) 带访问令牌调用
curl -s localhost:8080/api/protected/profile -H "Authorization: Bearer <accessToken>"

# 4) 一次性轮换；再用同一个 refreshToken 重放 -> 401 ROTATED 且整族失效
curl -s -X POST localhost:8080/api/auth/token/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

# 5) 主动撤销会话（旧通道，按刷新令牌撤销整族）
curl -s -X POST localhost:8080/api/auth/token/revoke \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

# 6) 多端会话：查看本人当前有效会话清单
curl -s localhost:8080/api/sessions -H "Authorization: Bearer <accessToken>"

# 7) 多端会话：按会话精准下线某一台设备（重复调用结论一致）
curl -s -X POST localhost:8080/api/sessions/<sessionId>/revoke \
  -H "Authorization: Bearer <accessToken>"
```

> 想在本地直观看到容量淘汰：把 `auth.max-sessions-per-user=2` 后连续登录三次
> （第二次后用第一台设备访问一次 profile 让它变“更活跃”），第三次登录会淘汰最久未活跃的设备；
> 再用被淘汰设备的令牌访问/续期即得到 401 `EVICTED`。所有时间推进在自动化测试里用
> `MutableClock` 完成，无需真实等待。

## 9. 设计取舍说明

- **内存状态**：OTP 挑战、失败计数、令牌族/刷新记录均在内存，重启即清空，符合
  “本地可运行、无外部服务”的目标；生产化时把 Store/Counter 换成持久实现即可，
  接口语义（原子消费、族级锁/用户级锁、窗口判定、LRU 选择）保持不变。
- **两级锁**：族锁串行化同一会话的轮换/撤销/淘汰；用户锁串行化同一账号“建会话 + 容量淘汰”，
  固定“先用户锁后族锁”的加锁顺序，既保证并发登录不超上限、不误伤新会话，也避免锁序死锁。
- **能力服务端快照**：会话的 roles/perms/scopes 存于令牌族，续期据此重签，
  不依赖用户目录的实时内容，保证“清单概要 = 访问令牌判定 = 续期后能力”三者一致、续期不丢能力。
- **终态先到先得且可区分**：会话终态为 REVOKED / EVICTED / 自然过期三类，分别落到
  `REVOKED` / `EVICTED` / `EXPIRED` 原因；撤销与淘汰互不改写，重复撤销幂等。
- **不回传明文**：OTP 与 refresh token 落库只存哈希；签名只证明令牌由本服务签发，
  是否有效仍以服务端状态（used / 会话终态 / exp）为准。
- **可解释失败**：登录、令牌、访问、会话四个层面各有独立 reason 枚举，HTTP 状态码与
  reason 双重区分，日志同步打印输入与判定依据。
- **向后兼容**：`issueFor` 无画像重载、`/api/auth/token/revoke` 旧通道、登录请求体中
  设备字段可选、`max-sessions-per-user<=0` 关闭上限，均保持改动前行为；原 32 个用例全部保留通过。
