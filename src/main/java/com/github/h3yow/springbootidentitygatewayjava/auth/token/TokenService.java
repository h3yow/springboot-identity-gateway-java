package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginClientContext;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * 令牌签发、校验、一次性轮换与撤销，并承载多端会话的容量控制。
 *
 * <p>多端会话规则：
 * <ul>
 *   <li>一次登录 = 一个令牌族 = 一个会话；同一账号可并行存在多个互不影响的会话。</li>
 *   <li>会话携带登录时的角色/权限/范围快照；刷新令牌内也保存同一份快照，
 *       续期后新访问令牌能力与快照严格一致，不会平白变少或消失。</li>
 *   <li>登录在<b>用户锁</b>内做容量检查：有效会话达到 {@code auth.max-sessions-per-user}
 *       时，淘汰 lastActiveAt 最小（最久未活跃）的那一个；新会话自身永不被选中。</li>
 *   <li>被淘汰会话得到 {@link TokenRejectionReason#EVICTED}，与主动撤销 {@code REVOKED}、
 *       自然过期 {@code EXPIRED}、重放 {@code ROTATED} 严格区分。</li>
 * </ul>
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";
    private static final String DEFAULT_DEVICE = "UNKNOWN-DEVICE";
    private static final String DEFAULT_CLIENT = "UNKNOWN-CLIENT";

    private final TokenStore store;
    private final TokenSigner signer;
    private final Clock clock;
    private final AuthProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public TokenService(TokenStore store, TokenSigner signer, Clock clock, AuthProperties properties) {
        this.store = store;
        this.signer = signer;
        this.clock = clock;
        this.properties = properties;
    }

    /** 兼容既有调用：未携带设备信息的登录。 */
    public IssuedTokens issueFor(UserAccount account) {
        return issueFor(account, LoginClientContext.unnamed());
    }

    /**
     * 登录成功后在用户锁内建立新会话：先按容量上限淘汰最久未活跃会话，再签发令牌对。
     * 并发登录因此被串行化，既不会超上限，也不会误伤刚建立的新会话。
     */
    public IssuedTokens issueFor(UserAccount account, LoginClientContext client) {
        long now = clock.nowMillis();
        String familyId = UUID.randomUUID().toString();
        LoginClientContext ctx = normalize(client);

        return store.withUserLock(account.username(), username -> {
            enforceCapacity(username, familyId, now);
            TokenFamily family = new TokenFamily(
                    familyId, username, now, false,
                    ctx.deviceId(), ctx.deviceName(), ctx.clientId(), now,
                    Set.copyOf(account.roles()), Set.copyOf(account.permissions()), Set.copyOf(account.scopes()),
                    SessionState.ACTIVE);
            store.saveFamily(family);
            log.info("建立会话: family={}, user={}, device={}, client={}",
                    familyId, username, ctx.deviceId(), ctx.clientId());
            return mintPair(family, account, now);
        });
    }

    /**
     * 容量控制：统计当前“有效”（ACTIVE 且未过刷新有效期）会话；达到上限则淘汰最久未活跃者。
     * 预留的新会话 id 仅用于日志，不参与候选，确保新会话永不被淘汰。
     */
    private void enforceCapacity(String username, String newFamilyId, long now) {
        int limit = properties.getMaxSessionsPerUser();
        if (limit <= 0) {
            return;
        }
        List<TokenFamily> active = store.familiesOf(username).stream()
                .filter(f -> f.state() == SessionState.ACTIVE)
                .filter(f -> now < f.lastActiveAt() + properties.getRefreshTokenTtlMillis())
                .toList();
        if (active.size() < limit) {
            return;
        }
        TokenFamily victim = active.stream()
                .min(Comparator.comparingLong(TokenFamily::lastActiveAt)
                        .thenComparing(TokenFamily::createdAt)
                        .thenComparing(TokenFamily::familyId))
                .orElseThrow(() -> new IllegalStateException("容量淘汰候选为空: " + username));
        store.withFamilyLock(victim.familyId(), fid -> {
            if (store.markEvicted(fid)) {
                log.warn("会话容量淘汰: user={}, 淘汰family={}, lastActiveAt={}, 依据=该会话最久未活跃; 新会话family={}",
                        username, fid, victim.lastActiveAt(), newFamilyId);
            }
            return null;
        });
    }

    /**
     * 校验访问令牌：结构与签名 -> 类型 -> 过期时间 -> 会话终态。
     *
     * @throws TokenException 各可区分原因（EXPIRED / REVOKED / EVICTED）
     */
    public AccessTokenClaims authenticate(String accessToken) {
        Map<String, Object> payload = parseAndVerify(accessToken, TYPE_ACCESS);
        String familyId = str(payload, "fam");
        String jti = str(payload, "jti");
        long expiresAt = longValue(payload, "exp");
        long now = clock.nowMillis();
        if (now >= expiresAt) {
            log.info("访问令牌拒绝: jti={}, family={}, 依据=已过期 now={} >= exp={}", jti, familyId, now, expiresAt);
            throw new TokenException(TokenRejectionReason.EXPIRED, "访问令牌已过期");
        }
        TokenFamily family = store.findFamily(familyId)
                .orElseThrow(() -> new TokenException(TokenRejectionReason.REVOKED, "会话不存在或已撤销"));
        rejectIfTerminal(family, "访问");
        // 会话刷新有效期已过：即便 access 的 exp 尚未到（边界情形）也以自然过期拒绝，并不再展示
        if (now >= family.lastActiveAt() + properties.getRefreshTokenTtlMillis()) {
            log.info("访问令牌拒绝: family={}, 依据=会话刷新有效期已过", familyId);
            throw new TokenException(TokenRejectionReason.EXPIRED, "会话已过期，请重新登录");
        }
        store.touchLastActive(familyId, now);
        return new AccessTokenClaims(
                jti, familyId, str(payload, "sub"),
                Set.copyOf(stringList(payload, "roles")),
                Set.copyOf(stringList(payload, "perms")),
                Set.copyOf(stringList(payload, "scopes")),
                longValue(payload, "iat"), expiresAt);
    }

    /**
     * 一次性轮换刷新令牌。
     * 重复/并发使用同一个刷新令牌：仅一次成功，其余请求失败且整个族被撤销（重放检测）。
     * 续期成功时刷新令牌中的能力快照原样继承到新令牌对，已授予能力不减少。
     */
    public IssuedTokens rotate(String refreshToken) {
        Map<String, Object> payload = parseAndVerify(refreshToken, TYPE_REFRESH);
        String familyId = str(payload, "fam");
        String tokenHash = signer.sha256Hex(refreshToken);

        return store.withFamilyLock(familyId, fid -> {
            StoredRefreshToken stored = store.findRefreshToken(tokenHash).orElse(null);
            if (stored == null) {
                log.warn("刷新拒绝: family={}, 依据=服务端无此刷新令牌记录", fid);
                throw new TokenException(TokenRejectionReason.UNKNOWN, "刷新令牌不被识别");
            }
            TokenFamily family = store.findFamily(fid)
                    .orElseThrow(() -> new TokenException(TokenRejectionReason.REVOKED, "会话不存在或已撤销"));
            rejectIfTerminal(family, "刷新");
            long now = clock.nowMillis();
            if (now >= stored.expiresAt()) {
                log.warn("刷新拒绝: family={}, 依据=刷新令牌已过期 now={} >= exp={}", fid, now, stored.expiresAt());
                throw new TokenException(TokenRejectionReason.EXPIRED, "刷新令牌已过期，需重新登录");
            }
            if (stored.used()) {
                // 重放检测：旧刷新令牌再次出现 -> 撤销整族（不覆盖用户主动撤销/淘汰）
                store.markReplayRevoked(fid);
                log.warn("检测到刷新令牌重放: family={}, 依据=令牌已被轮换使用，立即撤销整族，该会话全部令牌失效", fid);
                throw new TokenException(TokenRejectionReason.ROTATED,
                        "刷新令牌已被使用（疑似重放），会话已全部撤销，请重新登录");
            }
            // 原子地消费旧刷新令牌
            store.saveRefreshToken(stored.asUsed());
            UserAccount account = rehydrateAccount(stored.username(), payload);
            // 续期成功：更新会话最近活跃时间，能力以族上的登录快照为唯一来源
            store.touchLastActive(fid, now);
            TokenFamily activeFamily = store.findFamily(fid).orElse(family);
            IssuedTokens issued = mintPair(activeFamily, account, now);
            log.info("刷新成功并完成轮换: family={}, roles={}, perms={}, scopes={}, 旧刷新令牌已作废",
                    fid, account.roles(), account.permissions(), account.scopes());
            return issued;
        });
    }

    /** 主动撤销指定刷新令牌所属会话（族）；幂等，重复撤销结论一致且不抛异常。 */
    public void revoke(String refreshToken) {
        Map<String, Object> payload = parseAndVerify(refreshToken, TYPE_REFRESH);
        String familyId = str(payload, "fam");
        store.withFamilyLock(familyId, fid -> {
            store.revokeFamily(fid);
            log.info("会话已主动撤销: family={}", fid);
            return null;
        });
    }

    /** 按会话 id 撤销；终态幂等。供会话管理服务使用。 */
    public void revokeFamilyById(String familyId) {
        store.withFamilyLock(familyId, fid -> {
            store.revokeFamily(fid);
            return null;
        });
    }

    /** 按 id 读取族（会话管理服务据此做属主校验与清单构建）。 */
    public Optional<TokenFamily> findFamily(String familyId) {
        return store.findFamily(familyId);
    }

    /** 列出某用户全部族（会话管理服务据此过滤有效会话）。 */
    public List<TokenFamily> familiesOf(String username) {
        return store.familiesOf(username);
    }

    /** 当前时钟下会话是否仍“有效”：ACTIVE 且刷新有效期未过。 */
    public boolean isSessionEffective(TokenFamily family, long now) {
        return family.state() == SessionState.ACTIVE
                && now < family.lastActiveAt() + properties.getRefreshTokenTtlMillis();
    }

    /** 会话刷新有效期长度（毫秒）；会话到期时间 = lastActiveAt + 该值。 */
    public long refreshTtlMillis() {
        return properties.getRefreshTokenTtlMillis();
    }

    private void rejectIfTerminal(TokenFamily family, String action) {
        switch (family.state()) {
            case EVICTED -> {
                log.info("{}拒绝: family={}, 依据=会话因容量上限被淘汰", action, family.familyId());
                throw new TokenException(TokenRejectionReason.EVICTED,
                        "该会话已在其它设备登录时被淘汰，请重新登录");
            }
            case REVOKED -> {
                log.info("{}拒绝: family={}, 依据=会话已被用户主动撤销", action, family.familyId());
                throw new TokenException(TokenRejectionReason.REVOKED, "会话已被撤销");
            }
            case REPLAY_REVOKED -> {
                log.info("{}拒绝: family={}, 依据=会话因刷新令牌重放被整族撤销", action, family.familyId());
                throw new TokenException(TokenRejectionReason.REVOKED, "会话因检测到重放已被撤销，请重新登录");
            }
            case ACTIVE -> {
            }
        }
    }

    /** 在指定族内签发一对新令牌并落库刷新令牌哈希；能力取自族快照。 */
    private IssuedTokens mintPair(TokenFamily family, UserAccount account, long now) {
        Set<String> scopes = family.scopes();
        String access = mintAccessToken(family, scopes, now);
        String refresh = mintToken(TYPE_REFRESH, family.familyId(), account.username(), now,
                properties.getRefreshTokenTtlMillis(),
                Map.of("roles", family.roles(), "perms", family.permissions(), "scopes", family.scopes()));
        StoredRefreshToken stored = new StoredRefreshToken(
                signer.sha256Hex(refresh), family.familyId(), account.username(), now,
                now + properties.getRefreshTokenTtlMillis(), false);
        store.saveRefreshToken(stored);
        return new IssuedTokens(family.familyId(), access, refresh,
                now + properties.getAccessTokenTtlMillis(),
                now + properties.getRefreshTokenTtlMillis());
    }

    /** 生成新的访问令牌，角色/权限/范围以会话快照为准。 */
    String mintAccessToken(TokenFamily family, Set<String> scopes, long now) {
        return mintToken(TYPE_ACCESS, family.familyId(), family.username(), now,
                properties.getAccessTokenTtlMillis(),
                Map.of("roles", family.roles(), "perms", family.permissions(), "scopes", scopes));
    }

    /**
     * 轮换时仅凭刷新令牌载荷重建账户视图：角色/权限/范围以刷新令牌携带的快照为准，
     * 不依赖用户目录（目录可被独立撤销/变更），保证续期后能力与权限判定自洽。
     */
    private UserAccount rehydrateAccount(String username, Map<String, Object> refreshPayload) {
        Set<String> roles = Set.copyOf(stringList(refreshPayload, "roles"));
        Set<String> perms = Set.copyOf(stringList(refreshPayload, "perms"));
        Set<String> scopes = Set.copyOf(stringList(refreshPayload, "scopes"));
        return new UserAccount(username, "", roles, perms, scopes);
    }

    private String mintToken(String type, String familyId, String subject, long now, long ttlMillis,
                             Map<String, Object> extra) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("typ", type);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("fam", familyId);
        payload.put("sub", subject);
        payload.put("iat", now);
        payload.put("exp", now + ttlMillis);
        payload.putAll(extra);
        try {
            return signer.sign(objectMapper.writeValueAsBytes(payload));
        } catch (Exception ex) {
            throw new IllegalStateException("令牌签发序列化失败", ex);
        }
    }

    private Map<String, Object> parseAndVerify(String token, String expectedType) {
        byte[] payloadBytes = signer.verify(token);
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> payload = objectMapper.readValue(payloadBytes, Map.class);
            String type = str(payload, "typ");
            if (!expectedType.equals(type)) {
                log.info("令牌类型不符: 期望={}, 实际={}", expectedType, type);
                throw new TokenException(TokenRejectionReason.WRONG_TYPE,
                        "令牌类型错误，期望 " + expectedType);
            }
            return payload;
        } catch (TokenException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new TokenException(TokenRejectionReason.MALFORMED, "令牌载荷不合法");
        }
    }

    private static LoginClientContext normalize(LoginClientContext client) {
        if (client == null) {
            return LoginClientContext.unnamed();
        }
        String deviceId = client.deviceId() == null || client.deviceId().isBlank() ? DEFAULT_DEVICE : client.deviceId();
        String clientId = client.clientId() == null || client.clientId().isBlank() ? DEFAULT_CLIENT : client.clientId();
        String deviceName = client.deviceName() == null ? "" : client.deviceName();
        return new LoginClientContext(deviceId, deviceName, clientId);
    }

    private static String str(Map<String, Object> payload, String key) {
        Object value = payload.get(key);
        return value == null ? "" : value.toString();
    }

    private static long longValue(Map<String, Object> payload, String key) {
        Object value = payload.get(key);
        return value instanceof Number number ? number.longValue() : 0L;
    }

    @SuppressWarnings("unchecked")
    private static java.util.List<String> stringList(Map<String, Object> payload, String key) {
        Object value = payload.get(key);
        if (value instanceof java.util.List<?> list) {
            java.util.List<String> result = new java.util.ArrayList<>();
            for (Object item : list) {
                result.add(item == null ? "" : item.toString());
            }
            return result;
        }
        return java.util.List.of();
    }
}
