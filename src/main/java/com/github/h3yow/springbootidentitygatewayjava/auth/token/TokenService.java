package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.ClientInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionState;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * 令牌签发、校验、一次性轮换与撤销，并在其上承载多端会话管理。
 *
 * <p>刷新令牌轮换（Refresh Token Rotation）规则：
 * <ul>
 *   <li>每个刷新令牌仅能成功使用一次，成功后立即作废并签发新对令牌（同族）</li>
 *   <li>同一个刷新令牌并发或重复使用时：只有一次成功；其余请求得到 ROTATED 结论，
 *       且整个令牌族被撤销，该会话下已签发的访问/刷新令牌全部失效</li>
 *   <li>已过期 -> EXPIRED；已撤销族 -> REVOKED；容量淘汰 -> EVICTED；
 *       无法解析/验签 -> MALFORMED/BAD_SIGNATURE</li>
 * </ul>
 *
 * <p>多端会话规则：
 * <ul>
 *   <li>一次登录建立一个令牌族（一个会话），同一账号可并存多个会话</li>
 *   <li>建会话在用户锁内做容量判定：超过 {@code auth.max-sessions-per-user} 时，
 *       仅淘汰“当前仍有效、最久未活跃”的那一个旧会话（EVICTED），新会话正常建立</li>
 *   <li>会话能力（roles/perms/scopes）以服务端族快照为准，续期不减少也不丢失</li>
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

    /** 兼容无画像信息的登录（旧调用/旧测试）：客户端画像为 unknown。 */
    public IssuedTokens issueFor(UserAccount account) {
        return issueFor(account, ClientInfo.unknown());
    }

    /**
     * 登录成功后建立新会话（令牌族）并签发一对令牌。
     * 整个“容量判定 + 淘汰 + 建会话 + 签发”在该账号的用户锁内原子完成，
     * 保证并发登录绝不超过上限，且绝不会淘汰刚建立的新会话。
     */
    public IssuedTokens issueFor(UserAccount account, ClientInfo client) {
        long now = clock.nowMillis();
        ClientInfo safeClient = client == null ? ClientInfo.unknown() : client;
        return store.withUserLock(account.username(), username -> {
            enforceCapacity(username, now);
            String familyId = UUID.randomUUID().toString();
            long refreshExpiry = now + properties.getRefreshTokenTtlMillis();
            TokenFamily family = new TokenFamily(
                    familyId, username, now, now, refreshExpiry, SessionState.ACTIVE,
                    safeClient, account.roles(), account.permissions(), account.scopes());
            store.saveFamily(family);
            IssuedTokens issued = mintPair(family, account, now);
            log.info("建立会话: family={}, user={}, 设备={}, 客户端={}, 能力roles={},perms={},scopes={}",
                    familyId, username, safeClient.deviceType(), safeClient.clientId(),
                    account.roles(), account.permissions(), account.scopes());
            return issued;
        });
    }

    /**
     * 容量判定：当前仍有效（ACTIVE 且会话未到期）会话数达到上限时，
     * 仅淘汰其中最久未活跃的一个。过期/已终止会话不占位，也不参与淘汰。
     */
    private void enforceCapacity(String username, long now) {
        int limit = properties.getMaxSessionsPerUser();
        if (limit <= 0) {
            return;
        }
        var activeSessions = store.allFamilies().stream()
                .filter(f -> f.username().equals(username))
                .filter(f -> f.state() == SessionState.ACTIVE)
                .filter(f -> f.expiresAt() <= 0L || f.expiresAt() > now)
                .toList();
        if (activeSessions.size() < limit) {
            return;
        }
        activeSessions.stream()
                .min(Comparator.comparingLong(TokenFamily::lastActiveAt)
                        .thenComparing(TokenFamily::familyId))
                .ifPresent(victim -> store.withFamilyLock(victim.familyId(), fid -> {
                    TokenFamily current = store.findFamily(fid).orElse(null);
                    if (current != null && current.state() == SessionState.ACTIVE) {
                        store.evictFamily(fid);
                        log.warn("容量淘汰: user={}, 淘汰family={}, lastActiveAt={}, 依据=达到上限{}且该会话最久未活跃",
                                username, fid, current.lastActiveAt(), limit);
                    }
                    return null;
                }));
    }

    /**
     * 校验访问令牌：结构与签名 -> 类型 -> 过期时间 -> 会话状态。
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
        if (family.state() == SessionState.EVICTED) {
            log.info("访问令牌拒绝: jti={}, family={}, 依据=会话已被容量上限淘汰", jti, familyId);
            throw new TokenException(TokenRejectionReason.EVICTED, "会话已因达到并发上限被淘汰，需重新登录");
        }
        if (family.terminated()) {
            log.info("访问令牌拒绝: jti={}, family={}, 依据=所属会话已撤销(主动撤销或重放检测)", jti, familyId);
            throw new TokenException(TokenRejectionReason.REVOKED, "会话已被撤销");
        }
        // 成功访问更新最近活跃（LRU 依据），原子写不与族锁内变更竞争
        store.putFamily(family.touch(now, family.expiresAt()));
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
            if (family.state() == SessionState.EVICTED) {
                log.warn("刷新拒绝: family={}, 依据=会话此前已被容量上限淘汰", fid);
                throw new TokenException(TokenRejectionReason.EVICTED, "会话已被淘汰，需重新登录");
            }
            if (family.revoked()) {
                log.warn("刷新拒绝: family={}, 依据=会话此前已撤销（主动撤销或重放检测）", fid);
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
            // 能力以服务端会话快照为准，保证续期后角色/权限/范围不减少不丢失
            UserAccount account = rehydrateAccount(stored.username(), family);
            IssuedTokens issued = mintPair(family, account, now);
            // 滑动续期：刷新成功即活跃，会话到期随新刷新令牌顺延
            long refreshExpiry = now + properties.getRefreshTokenTtlMillis();
            store.putFamily(family.touch(now, refreshExpiry));
            log.info("刷新成功并完成轮换: family={}, 已续期能力roles={},perms={},scopes={}, 旧刷新令牌已作废",
                    fid, family.roles(), family.permissions(), family.scopes());
            return issued;
        });
    }

    /** 主动撤销指定刷新令牌所属会话（族）；幂等。 */
    public void revoke(String refreshToken) {
        Map<String, Object> payload = parseAndVerify(refreshToken, TYPE_REFRESH);
        String familyId = str(payload, "fam");
        revokeFamilyById(familyId);
    }

    /**
     * 按会话 id 精准撤销，终态“先到先得”：撤销与续期竞争时，
     * 若撤销先拿到族锁，后续续期看到 REVOKED 被拒，不会再换出新凭证。
     */
    public void revokeFamilyById(String familyId) {
        store.withFamilyLock(familyId, fid -> {
            store.findFamily(fid).ifPresentOrElse(
                    family -> {
                        store.putFamily(family.asRevoked());
                        log.info("会话已主动撤销: family={}, 原状态={}",
                                fid, family.state() == SessionState.ACTIVE ? "ACTIVE" : family.state());
                    },
                    () -> log.info("撤销请求: family={} 服务端无记录，按幂等返回成功", fid));
            return null;
        });
    }

    /** 在指定族内签发一对新令牌并落库刷新令牌哈希。 */
    private IssuedTokens mintPair(TokenFamily family, UserAccount account, long now) {
        String access = mintAccessToken(family.familyId(), account, account.scopes(), now);
        String refresh = mintToken(TYPE_REFRESH, family.familyId(), account.username(), now,
                properties.getRefreshTokenTtlMillis(),
                Map.of("roles", account.roles(), "perms", account.permissions(), "scopes", account.scopes()));
        StoredRefreshToken stored = new StoredRefreshToken(
                signer.sha256Hex(refresh), family.familyId(), account.username(), now,
                now + properties.getRefreshTokenTtlMillis(), false);
        store.saveRefreshToken(stored);
        return new IssuedTokens(access, refresh,
                now + properties.getAccessTokenTtlMillis(),
                now + properties.getRefreshTokenTtlMillis());
    }

    /** 生成新的访问令牌。 */
    String mintAccessToken(String familyId, UserAccount account, Set<String> scopes, long now) {
        return mintToken(TYPE_ACCESS, familyId, account.username(), now,
                properties.getAccessTokenTtlMillis(),
                Map.of("roles", account.roles(), "perms", account.permissions(), "scopes", scopes));
    }

    /**
     * 续期时仅凭服务端会话快照重建账户视图：角色/权限/范围以登录时授予并随会话保存的快照为准，
     * 不依赖用户目录（目录可被独立撤销/变更），保证结论自洽、续期不丢能力。
     */
    private UserAccount rehydrateAccount(String username, TokenFamily family) {
        return new UserAccount(username, "", family.roles(), family.permissions(), family.scopes());
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
