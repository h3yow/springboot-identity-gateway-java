package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * 令牌签发、校验、一次性轮换与撤销。
 *
 * <p>刷新令牌轮换（Refresh Token Rotation）规则：
 * <ul>
 *   <li>每个刷新令牌仅能成功使用一次，成功后立即作废并签发新对令牌（同族）</li>
 *   <li>同一个刷新令牌并发或重复使用时：只有一次成功；其余请求得到 ROTATED 结论，
 *       且整个令牌族被撤销，该会话下已签发的访问/刷新令牌全部失效</li>
 *   <li>已过期 -> EXPIRED；已撤销族 -> REVOKED；无法解析/验签 -> MALFORMED/BAD_SIGNATURE</li>
 * </ul>
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

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

    /** 登录成功后签发一对令牌，并建立新的令牌族。 */
    public IssuedTokens issueFor(UserAccount account) {
        long now = clock.nowMillis();
        String familyId = UUID.randomUUID().toString();
        store.saveFamily(new TokenFamily(familyId, account.username(), now, false));
        return mintPair(familyId, account, now);
    }

    /**
     * 校验访问令牌：结构与签名 -> 类型 -> 过期时间 -> 族撤销状态。
     *
     * @throws TokenException 各可区分原因
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
        if (family.revoked()) {
            log.info("访问令牌拒绝: jti={}, family={}, 依据=所属令牌族已撤销(重放检测或主动撤销)", jti, familyId);
            throw new TokenException(TokenRejectionReason.REVOKED, "会话已被撤销");
        }
        return new AccessTokenClaims(
                jti, familyId, str(payload, "sub"),
                Set.copyOf(stringList(payload, "roles")),
                Set.copyOf(stringList(payload, "perms")),
                Set.copyOf(stringList(payload, "scopes")),
                longValue(payload, "iat"), expiresAt);
    }

    /**
     * 一次性轮换刷新令牌。
     * 重复/并发使用同一个刷新令牌：仅一次成功，其余请求失败且整个族被撤销。
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
            if (family.revoked()) {
                log.warn("刷新拒绝: family={}, 依据=令牌族此前已撤销（检测到重放）", fid);
                throw new TokenException(TokenRejectionReason.REVOKED, "会话已被撤销，需重新登录");
            }
            long now = clock.nowMillis();
            if (now >= stored.expiresAt()) {
                log.warn("刷新拒绝: family={}, 依据=刷新令牌已过期 now={} >= exp={}", fid, now, stored.expiresAt());
                throw new TokenException(TokenRejectionReason.EXPIRED, "刷新令牌已过期，需重新登录");
            }
            if (stored.used()) {
                // 重放检测：旧刷新令牌再次出现 -> 撤销整族
                store.revokeFamily(fid);
                log.warn("检测到刷新令牌重放: family={}, 依据=令牌已被轮换使用，立即撤销整族，该会话全部令牌失效", fid);
                throw new TokenException(TokenRejectionReason.ROTATED,
                        "刷新令牌已被使用（疑似重放），会话已全部撤销，请重新登录");
            }
            // 原子地消费旧刷新令牌
            store.saveRefreshToken(stored.asUsed());
            UserAccount account = rehydrateAccount(stored.username(), payload);
            IssuedTokens issued = mintPair(fid, account, now);
            log.info("刷新成功并完成轮换: family={}, 新accessJti 已签发, 旧刷新令牌已作废", fid);
            return issued;
        });
    }

    /** 主动撤销指定刷新令牌所属会话（族）。 */
    public void revoke(String refreshToken) {
        Map<String, Object> payload = parseAndVerify(refreshToken, TYPE_REFRESH);
        String familyId = str(payload, "fam");
        store.withFamilyLock(familyId, fid -> {
            store.revokeFamily(fid);
            log.info("会话已主动撤销: family={}", fid);
            return null;
        });
    }

    /** 在指定族内签发一对新令牌并落库刷新令牌哈希。 */
    private IssuedTokens mintPair(String familyId, UserAccount account, long now) {
        String access = mintAccessToken(familyId, account, account.scopes());
        String refresh = mintToken(TYPE_REFRESH, familyId, account.username(), now,
                properties.getRefreshTokenTtlMillis(), Map.of());
        StoredRefreshToken stored = new StoredRefreshToken(
                signer.sha256Hex(refresh), familyId, account.username(), now,
                now + properties.getRefreshTokenTtlMillis(), false);
        store.saveRefreshToken(stored);
        return new IssuedTokens(access, refresh,
                now + properties.getAccessTokenTtlMillis(),
                now + properties.getRefreshTokenTtlMillis());
    }

    /** 生成新的访问令牌。 */
    String mintAccessToken(String familyId, UserAccount account, Set<String> scopes) {
        long now = clock.nowMillis();
        return mintToken(TYPE_ACCESS, familyId, account.username(), now,
                properties.getAccessTokenTtlMillis(),
                Map.of("roles", account.roles(), "perms", account.permissions(), "scopes", scopes));
    }

    /**
     * 轮换时仅凭刷新令牌载荷重建账户视图：角色/权限/范围以旧刷新令牌签发时的快照为准，
     * 不依赖用户目录（目录可被独立撤销/变更），保证结论自洽。
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
