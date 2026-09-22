# Spring Boot Identity Gateway（本地身份认证与会话令牌闭环）

一个可在本地直接运行的最小身份网关：**两步登录（密码 + 一次性动态验证码）**、
**访问/刷新令牌签发与一次性轮换（含重放检测）**、**基于角色/权限/范围的统一访问控制**。
不依赖数据库、短信/邮件渠道、真实第三方凭据或网络时间——用户目录为内存播种，
时间源可被测试完全控制。

## 1. 技术栈与运行要求

- Java 21+、Spring Boot 3.4.x、Spring MVC、JDK 内置 PBKDF2 / HMAC-SHA256
- 无外部中间件；构建：`mvn test`（含 32 个测试）

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
| `REVOKED` | 族已被重放检测或主动撤销 | 401 |
| `UNKNOWN` | 服务端无此刷新令牌记录 | 401 |

判定顺序：签名/类型 → 过期 → 族状态。时间一律取自可替换的 `Clock`，
测试用 `MutableClock` 手动推进，过期结论 100% 稳定复现。

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

## 7. 本地验证方法

### 7.1 自动化测试（推荐，不启动网络端口也能跑单元层）

```bash
mvn test                       # 全部 32 个测试
mvn test -Dtest=TokenServiceTest#concurrentRefreshExactlyOneSuccess
```

测试分层：

- `LoginServiceTest`（9）：凭据错误、OTP 过期/重放/错误/缺失、连续失败锁定、
  **锁定窗口到期自动恢复**（用 `MutableClock` 精确推进到到期前 1ms 与到期时刻）。
- `TokenServiceTest`（9）：签发校验、正常轮换、**16 线程并发刷新恰一次成功**、
  重放触发整族撤销且新老令牌全失效、access/refresh 过期、主动撤销、坏签名、
  错误类型、族隔离。
- `AccessControlServiceTest`（8）：三类拒绝原因边界、401 与 403 可区分。
- `AuthFlowIntegrationTest`（5）：MockMvc 全链路 HTTP 状态码与 reason 断言，
  时钟固定为 `MutableClock`，每个用例前清空 OTP/失败计数/令牌存储保证隔离。

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
```

## 8. 设计取舍说明

- **内存状态**：OTP 挑战、失败计数、令牌族/刷新记录均在内存，重启即清空，符合
  “本地可运行、无外部服务”的目标；生产化时把三个 Store/Counter 换成持久实现即可，
  接口语义（原子消费、族级锁、窗口判定）保持不变。
- **不回传明文**：OTP 与 refresh token 落库只存哈希；签名只证明令牌由本服务签发，
  是否有效仍以服务端状态（used / revoked / exp）为准。
- **可解释失败**：登录、令牌、访问三个层面各有独立 reason 枚举，HTTP 状态码与
  reason 双重区分，日志同步打印输入与判定依据。
