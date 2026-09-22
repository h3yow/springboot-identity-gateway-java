package com.github.h3yow.springbootidentitygatewayjava.token;

import java.time.Instant;

/** 一次签发或轮换产生的访问/刷新令牌对及其绝对过期时刻。 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt,
        String sessionId
) {
}
