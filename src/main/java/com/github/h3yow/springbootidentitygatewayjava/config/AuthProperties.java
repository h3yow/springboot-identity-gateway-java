package com.github.h3yow.springbootidentitygatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 认证相关可配置参数，前缀 auth.*。
 * 锁定时长、令牌寿命、OTP 寿命、种子用户均可在 application.properties 覆盖。
 */
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private int maxFailures = 5;
    private long lockSeconds = 300;
    private long otpTtlSeconds = 300;
    private long accessTokenTtlSeconds = 900;
    private long refreshTokenTtlSeconds = 1209600;
    private long sessionMaxTtlSeconds = 86400;
    /** 开发模式：种子用户密码以 plain: 前缀给出时按明文处理，仅用于本地/测试。 */
    private boolean devPlaintextPasswords = true;
    private List<SeedUser> users = new ArrayList<>();

    public int getMaxFailures() {
        return maxFailures;
    }

    public void setMaxFailures(int maxFailures) {
        this.maxFailures = maxFailures;
    }

    public long getLockSeconds() {
        return lockSeconds;
    }

    public void setLockSeconds(long lockSeconds) {
        this.lockSeconds = lockSeconds;
    }

    public long getOtpTtlSeconds() {
        return otpTtlSeconds;
    }

    public void setOtpTtlSeconds(long otpTtlSeconds) {
        this.otpTtlSeconds = otpTtlSeconds;
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(long refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public long getSessionMaxTtlSeconds() {
        return sessionMaxTtlSeconds;
    }

    public void setSessionMaxTtlSeconds(long sessionMaxTtlSeconds) {
        this.sessionMaxTtlSeconds = sessionMaxTtlSeconds;
    }

    public boolean isDevPlaintextPasswords() {
        return devPlaintextPasswords;
    }

    public void setDevPlaintextPasswords(boolean devPlaintextPasswords) {
        this.devPlaintextPasswords = devPlaintextPasswords;
    }

    public List<SeedUser> getUsers() {
        return users;
    }

    public void setUsers(List<SeedUser> users) {
        this.users = users;
    }

    /** 种子用户配置项。 */
    public static class SeedUser {
        private String username;
        private String password;
        private List<String> roles = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }
}
