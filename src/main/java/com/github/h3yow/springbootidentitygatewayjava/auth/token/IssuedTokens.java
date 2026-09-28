package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 签发结果：不透明访问令牌与刷新令牌，以及各自过期时间。
 *
 * @param sessionId 所属会话（令牌族）id，多端会话管理据此精准下线
 */
public record IssuedTokens(String sessionId,
                           String accessToken,
                           String refreshToken,
                           long accessTokenExpiresAt,
                           long refreshTokenExpiresAt) {

    /** 兼容不关注 sessionId 的既有调用。 */
    public IssuedTokens(String accessToken, String refreshToken,
                        long accessTokenExpiresAt, long refreshTokenExpiresAt) {
        this(null, accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt);
    }
}
