# Spring Boot Identity Gateway（本地身份认证与会话令牌闭环）

一个可在本地直接运行的最小身份网关，演示并验证：

- 密码 + 一次性动态验证码（OTP）的**两步登录**；
- 访问令牌 / 刷新令牌的签发、过期、轮换与撤销；
- 刷新令牌**一次性使用**，并发或重放只允许一次成功，其余请求失败并使该会话令牌整族失效；
- 基于**角色 + 权限范围**的访问控制，未认证 / 角色不足 / 范围不足三类结论可区分，默认拒绝；
- 所有时间判定可通过可控时钟在测试中**稳定复现**，不依赖外部服务、真实凭据或网络时间。

技术栈：Java 21、Spring Boot 3.4.1、Spring MVC 拦截器、JDK 内置 PBKDF2WithHmacSHA256、
内存存储（ConcurrentHashMap）。无数据库、无消息中间件、无第三方认证服务。

---

## 1. 两步登录流程

```
客户端                         网关
 │  POST /api/auth/login/password
 │  { username, password }
 ├──────────────────────────────►│ 校验账户锁定状态
 │                               │ 校验口令（PBKDF2）
 │                               │ 失败：计入连续失败，达阈值临时锁定
 │  200 { pendingToken, otpHint, otpExpiresAt }
 │◄──────────────────────────────┤ 生成一次性 6 位 OTP（本地演示在响应中回显）
 │  POST /api/auth/login/otp
 │  { pendingToken, otp }
 ├──────────────────────────────►│ 依次判定：锁定 → OTP 过期 → OTP 一次性（CAS）→ OTP 正确性
 │  200 { accessToken, refreshToken, ... }
 │◄──────────────────────────────┤ 成功后重置失败计数并签发令牌对
```

判定顺序（越靠前优先级越高），每种失败都有独立错误码：

| 场景 | 错误码 | HTTP |
| --- | --- | --- |
| 用户名/密码错误（未达锁定阈值） | `LOGIN_BAD_CREDENTIALS` | 401 |
| 连续失败达到阈值（触发锁定的当次请求即如此）/ 锁定期内登录 | `LOGIN_ACCOUNT_LOCKED` | 423 |
| OTP 错误 | `OTP_INVALID` | 401 |
| OTP 已过 TTL | `OTP_EXPIRED` | 401 |
| OTP 重复提交（含并发，非首次成功者） | `OTP_REPLAYED` | 409 |
| pendingToken 不存在/无效 | `PENDING_LOGIN_NOT_FOUND` | 401 |

- OTP 一次性消费基于 `AtomicBoolean.compareAndSet`，**并发提交恰好一次成功**。
- 第一步与第二步的失败都计入连续失败计数；达到 `auth.max-failures` 即锁定。
- 锁定时长由 `auth.lock-seconds` 配置；采用**惰性恢复**，锁定窗口到期后下一次请求自动清空计数、恢复可登录，无需后台定时任务。

## 2. 令牌生命周期

一次登录创建一个**令牌会话（session）**，该会话下签发的所有访问令牌共享同一生死。

- **访问令牌（access token）**：不透明随机串（`at_` 前缀），默认 15 分钟有效，用于访问受保护资源。
- **刷新令牌（refresh token）**：不透明随机串（`rt_` 前缀），默认 14 天有效，**一次性**。
- **会话绝对上限**：`auth.session-max-ttl-seconds`（默认 24 小时），无论刷新多少次，超过即整族失效。

刷新轮换（`POST /api/auth/refresh`）的判定顺序：

1. 用刷新令牌定位会话（当前索引，或“已轮换旧令牌”重放索引）；
2. 会话是否过绝对有效期 → `TOKEN_EXPIRED`；
3. 会话是否已因子先前重放被吊销 → `REFRESH_REPLAYED`；是否因登出/其他原因撤销 → `SESSION_REVOKED`；
4. 出示的令牌是否为“当前”刷新令牌。旧值（已被轮换，含并发重复提交）即**重放**：
   将会话置为 `REVOKED_REPLAYED`，该会话下**所有访问令牌与刷新令牌立即失效**，返回 `REFRESH_REPLAYED`；
5. 当前刷新令牌自身是否过期 → `TOKEN_EXPIRED`；
6. 全部通过：旧刷新令牌移入重放索引，签发新的访问/刷新令牌对。

同一会话内的刷新操作由会话级锁串行化，因此 16 个并发请求使用同一刷新令牌时
**恰好 1 次成功，其余 15 次全部 `REFRESH_REPLAYED`**，且唯一成功者随后也无法再使用新令牌（整族已吊销）。

访问令牌校验（携带 `Authorization: Bearer <token>`）的错误码：

| 场景 | 错误码 | HTTP |
| --- | --- | --- |
| 缺少/无 Bearer 头 | `TOKEN_MISSING` | 401 |
| 服务端无此令牌记录 | `TOKEN_MALFORMED` | 401 |
| 访问令牌自身过期 | `TOKEN_EXPIRED` | 401 |
| 会话过绝对有效期 | `TOKEN_EXPIRED` | 401 |
| 会话被登出或重放吊销 | `TOKEN_REVOKED` | 401 |
| 已撤销/过期的刷新令牌再使用 | `REFRESH_REPLAYED` / `TOKEN_EXPIRED` | 401 |

登出（`POST /api/auth/logout`，需携带有效访问令牌）撤销整个会话，
其下尚未过期的访问令牌立即 `TOKEN_REVOKED`，刷新令牌无法再使用。

## 3. 访问控制规则

统一由 `AuthInterceptor` 在所有 `/api/**` 入口执行（登录与 refresh 端点显式公开），
各受保护入口判定一致，**默认拒绝**：

1. 非控制器方法、以及未标注 `@RequireScope` 的控制器方法 → 默认拒绝；
2. 令牌校验未通过 → 401（`TOKEN_*`，未认证）；
3. 角色不满足 → 403 `ACCESS_DENIED_ROLE`（已认证但无权限）；
4. 权限范围不覆盖目标 → 403 `ACCESS_DENIED_SCOPE`（令牌权限不足）。

`@RequireScope` 语义：

- `@RequireScope`：仅需登录；
- `@RequireScope("orders:read")`：需要该范围（多值满足其一即可）；
- `@RequireScope(value = "admin:write", roles = "admin")`：先要求 admin 角色，再要求 admin:write 范围。

内置演示资源：

| 端点 | 要求 |
| --- | --- |
| `GET /api/resources/profile` | 仅登录 |
| `GET /api/resources/orders` | 范围 `orders:read` |
| `GET /api/resources/admin` | 角色 `admin` 且范围 `admin:write` |

判定依据（所需角色/范围与主体实际角色/范围）会写入日志，便于解释每次允许/拒绝的结论。

## 4. 配置项（`src/main/resources/application.properties`）

| 配置键 | 默认值 | 含义 |
| --- | --- | --- |
| `auth.max-failures` | 5 | 触发临时锁定的连续失败次数 |
| `auth.lock-seconds` | 300 | 锁定时长（秒），到期自动恢复 |
| `auth.otp-ttl-seconds` | 300 | 一次性验证码有效期 |
| `auth.access-token-ttl-seconds` | 900 | 访问令牌有效期 |
| `auth.refresh-token-ttl-seconds` | 1209600 | 刷新令牌有效期 |
| `auth.session-max-ttl-seconds` | 86400 | 会话绝对有效期上限 |
| `auth.dev-plaintext-passwords` | true | 是否允许 `plain:` 前缀的种子明文口令 |
| `auth.users[n].*` | 见文件 | 内存种子用户（用户名、口令、角色、范围） |

内置演示用户（**仅本地演示，非真实凭据**）：

| 用户 | 密码 | 角色 | 范围 |
| --- | --- | --- | --- |
| alice | `alice-pw` | user | `orders:read` |
| bob | `bob-pw` | user | `profile:read` |
| admin | `admin-pw` | admin, user | `orders:read`, `admin:write` |

生产环境应将 `auth.dev-plaintext-passwords` 置为 `false`，并把口令配置为
`pbkdf2$<iterations>$<saltB64>$<hashB64>` 形式的哈希（与 `Pbkdf2PasswordEncoder` 输出一致）。

## 5. 本地验证方法

### 5.1 运行测试（离线，无需网络）

```bash
mvn -o test
```

测试组成（共 24 个，全部为无外部依赖的确定性测试）：

- `PasswordEncoderTest`：PBKDF2 编码/校验、随机盐、错误口令拒绝；
- `LoginLockTest`：达阈值锁定、窗口内仍锁定、窗口到期惰性恢复、成功登录重置计数；
- `LoginServiceTest`：错误凭据、OTP 错误/过期/重复、未知 pendingToken、锁定与到期、
  **8 线程并发提交同一 OTP 恰好一次成功**；
- `TokenServiceTest`：正常轮换、旧刷新令牌重放吊销整族、
  **16 线程并发刷新恰好一次成功**、访问/刷新令牌过期区分、会话绝对过期、登出撤销、缺失/畸形令牌；
- `AuthInterceptorTest`：未认证、范围不足、角色不足、角色满足但范围不足、正常放行、默认拒绝；
- `AuthFlowIntegrationTest`：基于 MockMvc 的完整 HTTP 闭环（登录→OTP→访问→刷新重放→登出失效）。

过期与锁定场景使用 `MutableTimeProvider`（固定起点 + 手动 `advanceSeconds`），
**不调用 `Thread.sleep`、不依赖系统时钟流逝**，结果稳定可复现。
每个用例日志均打印输入参数与判定依据（错误码、所需与实际角色/范围、时间窗口等）。

### 5.2 启动应用并手工验证

```bash
mvn -o spring-boot:run
# 或：mvn -o package -DskipTests && java -jar target/springboot-identity-gateway-java-1.0-SNAPSHOT.jar
```

```bash
BASE=http://localhost:8080

# 第一步：密码
curl -s -X POST $BASE/api/auth/login/password \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pw"}'
# => {"pendingToken":"...","otpHint":"467639","otpExpiresAt":"..."}

# 第二步：用上一步返回的 pendingToken 与 otpHint（真实部署中 OTP 应通过侧信道发送）
curl -s -X POST $BASE/api/auth/login/otp \
  -H 'Content-Type: application/json' \
  -d '{"pendingToken":"<pendingToken>","otp":"<otpHint>"}'
# => {"accessToken":"at_...","refreshToken":"rt_...","sessionId":"sess_...", ...}

# 携带访问令牌访问受保护资源
curl -s $BASE/api/resources/orders -H 'Authorization: Bearer <accessToken>'

# 刷新（一次性）
curl -s -X POST $BASE/api/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

# 再次使用同一个旧 refreshToken => 401 REFRESH_REPLAYED，整族令牌失效
# 登出 => 当前会话全部令牌立即失效
curl -s -X POST $BASE/api/auth/logout -H 'Authorization: Bearer <accessToken>'
```

## 6. 代码结构

```
support/    TimeProvider 抽象（SystemTimeProvider 生产 / MutableTimeProvider 测试）
config/     AuthProperties（auth.* 配置）、AuthConfig
error/      ErrorCode 可区分错误码、ApiException、全局异常处理、统一错误响应体
model/      AppUser
user/       PasswordEncoder / Pbkdf2PasswordEncoder、UserStore（内存种子用户）
auth/       两步登录：LoginService、PendingLogin(Store)、OtpGenerator、LoginFailureTracker
token/      TokenService（签发/轮换/重放/撤销/校验）、TokenSession、SessionStore、AccessTokenStore
security/   Authentication、@RequireScope、AuthInterceptor（统一鉴权，默认拒绝）
web/        AuthController、ProtectedController、WebMvcConfig、DTO
```
