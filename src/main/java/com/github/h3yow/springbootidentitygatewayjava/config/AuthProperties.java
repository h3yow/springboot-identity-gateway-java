package com.github.h3yow.springbootidentitygatewayjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 认证相关可配置参数（前缀 auth）。
 */
@Component
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    /** 触发临时锁定的连续失败次数。 */
    private int maxFailures = 5;

    /** 临时锁定时长（毫秒）。 */
    private long lockMillis = 5 * 60_000L;

    /** 一次性验证码有效期（毫秒）。 */
    private long otpTtlMillis = 5 * 60_000L;

    /** 访问令牌有效期（毫秒）。 */
    private long accessTokenTtlMillis = 15 * 60_000L;

    /** 刷新令牌有效期（毫秒）。 */
    private long refreshTokenTtlMillis = 7 * 24 * 60 * 60_000L;

    /**
     * 单个账号同时有效的最大会话（设备）数量；达到上限后新登录优先淘汰最久未活跃会话。
     * 小于等于 0 表示不限制（保留不启用容量上限时的既有行为）。
     */
    private int maxSessionsPerUser = 5;

    /** 令牌签名密钥（HMAC-SHA256，Base64URL 编码）。 */
    private String tokenSigningKey = "ZGVmYXVsdC1sb2NhbC1kZXYta2V5LWNoYW5nZS1tZS1wbGVhc2U=";

    /** 本地开发模式：step1 响应中回显验证码，便于无外发渠道时本地验证。 */
    private boolean exposeOtpForLocalDev = true;

    public int getMaxFailures() { return maxFailures; }
    public void setMaxFailures(int maxFailures) { this.maxFailures = maxFailures; }

    public long getLockMillis() { return lockMillis; }
    public void setLockMillis(long lockMillis) { this.lockMillis = lockMillis; }

    public long getOtpTtlMillis() { return otpTtlMillis; }
    public void setOtpTtlMillis(long otpTtlMillis) { this.otpTtlMillis = otpTtlMillis; }

    public long getAccessTokenTtlMillis() { return accessTokenTtlMillis; }
    public void setAccessTokenTtlMillis(long accessTokenTtlMillis) { this.accessTokenTtlMillis = accessTokenTtlMillis; }

    public long getRefreshTokenTtlMillis() { return refreshTokenTtlMillis; }
    public void setRefreshTokenTtlMillis(long refreshTokenTtlMillis) { this.refreshTokenTtlMillis = refreshTokenTtlMillis; }

    public int getMaxSessionsPerUser() { return maxSessionsPerUser; }
    public void setMaxSessionsPerUser(int maxSessionsPerUser) { this.maxSessionsPerUser = maxSessionsPerUser; }

    public String getTokenSigningKey() { return tokenSigningKey; }
    public void setTokenSigningKey(String tokenSigningKey) { this.tokenSigningKey = tokenSigningKey; }

    public boolean isExposeOtpForLocalDev() { return exposeOtpForLocalDev; }
    public void setExposeOtpForLocalDev(boolean exposeOtpForLocalDev) { this.exposeOtpForLocalDev = exposeOtpForLocalDev; }
}
