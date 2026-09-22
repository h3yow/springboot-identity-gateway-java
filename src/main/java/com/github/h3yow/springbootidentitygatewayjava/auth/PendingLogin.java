package com.github.h3yow.springbootidentitygatewayjava.auth;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

/** 第一步通过后的待完成登录：持有待校验 OTP 及其一次性状态。 */
public final class PendingLogin {

    private final String pendingToken;
    private final String username;
    private final String otpCode;
    private final Set<String> roles;
    private final Set<String> scopes;
    private final Instant expiresAt;
    private final AtomicBoolean consumed = new AtomicBoolean(false);

    public PendingLogin(String pendingToken, String username, String otpCode,
                        Set<String> roles, Set<String> scopes, Instant expiresAt) {
        this.pendingToken = pendingToken;
        this.username = username;
        this.otpCode = otpCode;
        this.roles = roles;
        this.scopes = scopes;
        this.expiresAt = expiresAt;
    }

    public String pendingToken() { return pendingToken; }
    public String username() { return username; }
    public String otpCode() { return otpCode; }
    public Set<String> roles() { return roles; }
    public Set<String> scopes() { return scopes; }
    public Instant expiresAt() { return expiresAt; }
    public boolean consumed() { return consumed.get(); }

    /** CAS 式一次性消费：仅首个调用返回 true，重复提交一律 false。 */
    public boolean markConsumed() {
        return consumed.compareAndSet(false, true);
    }
}
