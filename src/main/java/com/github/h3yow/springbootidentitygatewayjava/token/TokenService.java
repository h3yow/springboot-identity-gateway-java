package com.github.h3yow.springbootidentitygatewayjava.token;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.error.ApiException;
import com.github.h3yow.springbootidentitygatewayjava.error.ErrorCode;
import com.github.h3yow.springbootidentitygatewayjava.support.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 令牌生命周期服务：
 * - 签发访问/刷新令牌对并建立会话；
 * - 刷新令牌一次性使用，并发或重放仅一次成功，其余导致整族令牌失效；
 * - 支持按会话撤销（登出）；
 * - 校验访问令牌的存在性、有效期与所属会话状态。
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final String ACCESS_PREFIX = "at_";
    private static final String REFRESH_PREFIX = "rt_";
    private static final String SESSION_PREFIX = "sess_";

    private final AuthProperties properties;
    private final TimeProvider timeProvider;
    private final SessionStore sessionStore;
    private final AccessTokenStore accessTokenStore;
    private final SecureRandom random = new SecureRandom();
    /** 每个会话一把锁，保证同会话并发刷新下“一次性使用”判定串行且一致。 */
    private final Map<String, Object> sessionLocks = new ConcurrentHashMap<>();

    public TokenService(AuthProperties properties, TimeProvider timeProvider,
                        SessionStore sessionStore, AccessTokenStore accessTokenStore) {
        this.properties = properties;
        this.timeProvider = timeProvider;
        this.sessionStore = sessionStore;
        this.accessTokenStore = accessTokenStore;
    }

    public TokenPair issue(String username, Set<String> roles, Set<String> scopes) {
        Instant now = timeProvider.now();
        String sessionId = SESSION_PREFIX + newToken();
        String accessToken = ACCESS_PREFIX + newToken();
        String refreshToken = REFRESH_PREFIX + newToken();
        Instant accessExpiry = now.plusSeconds(properties.getAccessTokenTtlSeconds());
        Instant refreshExpiry = now.plusSeconds(properties.getRefreshTokenTtlSeconds());
        Instant absoluteExpiry = now.plusSeconds(properties.getSessionMaxTtlSeconds());

        TokenSession session = new TokenSession(sessionId, username,
                Set.copyOf(roles), Set.copyOf(scopes), now, absoluteExpiry,
                refreshToken, refreshExpiry);
        sessionStore.put(session, refreshToken);
        accessTokenStore.put(new StoredAccessToken(accessToken, sessionId, username, accessExpiry));
        sessionLocks.put(sessionId, new Object());
        log.info("签发令牌: sessionId={}, username={}, roles={}, scopes={}, accessExpiry={}, refreshExpiry={}",
                sessionId, username, roles, scopes, accessExpiry, refreshExpiry);
        return new TokenPair(accessToken, refreshToken, accessExpiry, refreshExpiry, sessionId);
    }

    /**
     * 使用一次性刷新令牌轮换。
     * 判定顺序：定位会话（当前索引或已轮换重放索引）-> 绝对过期 -> 会话状态
     * -> 令牌是否为当前值（重放检测）-> 刷新令牌自身过期。
     * 任一非法都给出可区分错误码；重放撤销整族，后续同族请求一律失败。
     */
    public TokenPair refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "refreshToken 不能为空");
        }
        boolean presentedViaRotatedIndex = sessionStore.findByRefreshToken(refreshToken).isEmpty();
        TokenSession session = sessionStore.findByRefreshToken(refreshToken)
                .or(() -> sessionStore.findByRotatedToken(refreshToken))
                .orElse(null);
        if (session == null) {
            log.warn("刷新失败，刷新令牌无法定位到任何会话: tokenTail={}", tail(refreshToken));
            throw new ApiException(ErrorCode.REFRESH_REPLAYED,
                    "刷新令牌已被使用或无效，重放将使会话失效");
        }

        Object lock = sessionLocks.computeIfAbsent(session.sessionId(), k -> new Object());
        synchronized (lock) {
            Instant now = timeProvider.now();
            if (!now.isBefore(session.absoluteExpiresAt())) {
                session.revoke(TokenSession.State.REVOKED_EXPIRED);
                log.warn("刷新失败，会话绝对过期: sessionId={}, absoluteExpiry={}, now={}",
                        session.sessionId(), session.absoluteExpiresAt(), now);
                throw new ApiException(ErrorCode.TOKEN_EXPIRED, "会话已过期");
            }
            if (session.state() == TokenSession.State.REVOKED_REPLAY) {
                log.warn("刷新失败，会话已因子先前重放被撤销: sessionId={}", session.sessionId());
                throw new ApiException(ErrorCode.REFRESH_REPLAYED,
                        "刷新令牌重复使用，该会话全部令牌已失效");
            }
            if (session.state() != TokenSession.State.ACTIVE) {
                log.warn("刷新失败，会话已撤销: sessionId={}, state={}",
                        session.sessionId(), session.state());
                throw new ApiException(ErrorCode.SESSION_REVOKED, "会话已被撤销: " + session.state());
            }
            // 重放检测：仅当前刷新令牌可成功。旧值（已被轮换掉，含并发重复提交）即重放。
            if (presentedViaRotatedIndex || !refreshToken.equals(session.currentRefreshToken())) {
                session.revoke(TokenSession.State.REVOKED_REPLAY);
                log.error("检测到刷新令牌重放，撤销整族令牌: sessionId={}, username={}, presentedTail={}, currentTail={}",
                        session.sessionId(), session.username(),
                        tail(refreshToken), tail(session.currentRefreshToken()));
                throw new ApiException(ErrorCode.REFRESH_REPLAYED,
                        "刷新令牌重复使用，该会话全部令牌已失效");
            }
            if (!now.isBefore(session.refreshExpiresAt())) {
                session.revoke(TokenSession.State.REVOKED_EXPIRED);
                log.warn("刷新失败，刷新令牌已过期: sessionId={}, refreshExpiry={}, now={}",
                        session.sessionId(), session.refreshExpiresAt(), now);
                throw new ApiException(ErrorCode.TOKEN_EXPIRED, "刷新令牌已过期");
            }

            String oldRefresh = session.currentRefreshToken();
            String newAccess = ACCESS_PREFIX + newToken();
            String newRefresh = REFRESH_PREFIX + newToken();
            Instant accessExpiry = now.plusSeconds(properties.getAccessTokenTtlSeconds());
            Instant refreshExpiry = now.plusSeconds(properties.getRefreshTokenTtlSeconds());

            session.rotate(newRefresh, refreshExpiry);
            sessionStore.rebindRefresh(oldRefresh, newRefresh, session.sessionId());
            accessTokenStore.put(new StoredAccessToken(newAccess, session.sessionId(),
                    session.username(), accessExpiry));
            log.info("刷新令牌一次性轮换成功: sessionId={}, username={}, oldTail={}, newTail={}",
                    session.sessionId(), session.username(), tail(oldRefresh), tail(newRefresh));
            return new TokenPair(newAccess, newRefresh, accessExpiry, refreshExpiry,
                    session.sessionId());
        }
    }

    /**
     * 校验访问令牌：存在且未过期且所属会话仍 ACTIVE。
     * 过期与撤销给出不同错误码，便于区分失败原因。
     */
    public StoredAccessToken verifyAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new ApiException(ErrorCode.TOKEN_MISSING, "缺少访问令牌");
        }
        StoredAccessToken stored = accessTokenStore.find(accessToken).orElse(null);
        if (stored == null) {
            log.warn("访问令牌校验失败，服务端无记录: tokenTail={}", tail(accessToken));
            throw new ApiException(ErrorCode.TOKEN_MALFORMED, "访问令牌无效或已撤销");
        }
        if (!timeProvider.now().isBefore(stored.expiresAt())) {
            log.warn("访问令牌校验失败，已过期: sessionId={}, expiry={}, now={}",
                    stored.sessionId(), stored.expiresAt(), timeProvider.now());
            throw new ApiException(ErrorCode.TOKEN_EXPIRED, "访问令牌已过期");
        }
        TokenSession session = sessionStore.findById(stored.sessionId()).orElse(null);
        if (session == null || session.state() == TokenSession.State.REVOKED_LOGOUT
                || session.state() == TokenSession.State.REVOKED_REPLAY) {
            String state = session == null ? "ABSENT" : session.state().name();
            log.warn("访问令牌校验失败，所属会话不可用: sessionId={}, state={}",
                    stored.sessionId(), state);
            throw new ApiException(ErrorCode.TOKEN_REVOKED, "令牌所属会话已撤销");
        }
        if (session.state() == TokenSession.State.REVOKED_EXPIRED
                || !timeProvider.now().isBefore(session.absoluteExpiresAt())) {
            if (session.state() == TokenSession.State.ACTIVE) {
                session.revoke(TokenSession.State.REVOKED_EXPIRED);
            }
            log.warn("访问令牌校验失败，会话已过绝对有效期: sessionId={}, absoluteExpiry={}, now={}",
                    stored.sessionId(), session.absoluteExpiresAt(), timeProvider.now());
            throw new ApiException(ErrorCode.TOKEN_EXPIRED, "会话已过期");
        }
        return stored;
    }

    /** 按会话撤销（登出）：该会话下全部令牌立即失效。 */
    public void revokeSession(String sessionId) {
        TokenSession session = sessionStore.findById(sessionId).orElse(null);
        if (session == null) {
            return;
        }
        Object lock = sessionLocks.computeIfAbsent(sessionId, k -> new Object());
        synchronized (lock) {
            String oldRefresh = session.currentRefreshToken();
            session.revoke(TokenSession.State.REVOKED_LOGOUT);
            sessionStore.unbindRefresh(oldRefresh, sessionId);
        }
        log.info("会话已按登出撤销: sessionId={}", sessionId);
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String tail(String token) {
        if (token == null || token.length() < 6) {
            return "***";
        }
        return "…" + token.substring(token.length() - 6);
    }
}
