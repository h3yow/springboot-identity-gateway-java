package com.github.h3yow.springbootidentitygatewayjava.auth;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.support.TimeProvider;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** 待完成登录的内存存储，负责创建、取出与一次性删除。 */
@Component
public class PendingLoginStore {

    private final ConcurrentHashMap<String, PendingLogin> pendings = new ConcurrentHashMap<>();
    private final AuthProperties properties;
    private final TimeProvider timeProvider;
    private final SecureRandom random = new SecureRandom();

    public PendingLoginStore(AuthProperties properties, TimeProvider timeProvider) {
        this.properties = properties;
        this.timeProvider = timeProvider;
    }

    /** 为已通过第一步的用户创建一条待完成登录，返回其句柄（含 OTP 与 pendingToken）。 */
    public PendingLogin create(String username, String otpCode, Set<String> roles, Set<String> scopes) {
        purgeExpired();
        String pendingToken = newToken();
        Instant expiresAt = timeProvider.now().plusSeconds(properties.getOtpTtlSeconds());
        PendingLogin pending = new PendingLogin(pendingToken, username, otpCode, roles, scopes, expiresAt);
        pendings.put(pendingToken, pending);
        return pending;
    }

    public Optional<PendingLogin> find(String pendingToken) {
        if (pendingToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(pendings.get(pendingToken));
    }

    /** 惰性清理已过期记录，避免无限增长。 */
    private void purgeExpired() {
        Instant now = timeProvider.now();
        pendings.entrySet().removeIf(e -> !now.isBefore(e.getValue().expiresAt()));
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
