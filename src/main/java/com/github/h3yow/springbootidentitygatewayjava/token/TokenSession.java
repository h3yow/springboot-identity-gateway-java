package com.github.h3yow.springbootidentitygatewayjava.token;

import java.time.Instant;
import java.util.Set;

/**
 * 令牌会话（刷新令牌族）。
 * 一次登录产生一个会话；该会话下所有访问令牌共享同一生死。
 * 刷新令牌一次性使用：族内仅 currentRefreshToken 可用，使用旧值即视为重放。
 */
public final class TokenSession {

    public enum State { ACTIVE, REVOKED_LOGOUT, REVOKED_REPLAY, REVOKED_EXPIRED }

    private final String sessionId;
    private final String username;
    private final Set<String> roles;
    private final Set<String> scopes;
    private final Instant createdAt;
    private final Instant absoluteExpiresAt;
    private volatile State state = State.ACTIVE;
    private volatile String currentRefreshToken;
    private volatile Instant refreshExpiresAt;

    public TokenSession(String sessionId, String username, Set<String> roles, Set<String> scopes,
                        Instant createdAt, Instant absoluteExpiresAt,
                        String currentRefreshToken, Instant refreshExpiresAt) {
        this.sessionId = sessionId;
        this.username = username;
        this.roles = roles;
        this.scopes = scopes;
        this.createdAt = createdAt;
        this.absoluteExpiresAt = absoluteExpiresAt;
        this.currentRefreshToken = currentRefreshToken;
        this.refreshExpiresAt = refreshExpiresAt;
    }

    public String sessionId() { return sessionId; }
    public String username() { return username; }
    public Set<String> roles() { return roles; }
    public Set<String> scopes() { return scopes; }
    public Instant createdAt() { return createdAt; }
    public Instant absoluteExpiresAt() { return absoluteExpiresAt; }
    public State state() { return state; }
    public String currentRefreshToken() { return currentRefreshToken; }
    public Instant refreshExpiresAt() { return refreshExpiresAt; }

    /** 轮换为新的一次性刷新令牌；仅在 ACTIVE 状态下有意义。 */
    public void rotate(String newRefreshToken, Instant newRefreshExpiresAt) {
        this.currentRefreshToken = newRefreshToken;
        this.refreshExpiresAt = newRefreshExpiresAt;
    }

    /** 撤销整个会话，撤销后该族下所有令牌不再被接受。 */
    public void revoke(State reason) {
        this.state = reason;
        this.currentRefreshToken = null;
        this.refreshExpiresAt = null;
    }
}
