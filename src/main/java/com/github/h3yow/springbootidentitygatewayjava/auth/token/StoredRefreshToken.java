package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 刷新令牌的服务端记录（只保存令牌哈希）。
 */
public record StoredRefreshToken(String tokenHash, String familyId, String username,
                                 long issuedAt, long expiresAt, boolean used) {

    /** 返回标记为已使用（已轮换）的新实例。 */
    public StoredRefreshToken asUsed() {
        return new StoredRefreshToken(tokenHash, familyId, username, issuedAt, expiresAt, true);
    }
}
