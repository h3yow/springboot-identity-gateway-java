package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 签发结果：不透明访问令牌与刷新令牌，以及各自过期时间。
 */
public record IssuedTokens(String accessToken, String refreshToken,
                           long accessTokenExpiresAt, long refreshTokenExpiresAt) {
}
