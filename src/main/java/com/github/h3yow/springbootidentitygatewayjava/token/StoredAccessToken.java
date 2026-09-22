package com.github.h3yow.springbootidentitygatewayjava.token;

import java.time.Instant;

/** 已签发访问令牌的服务端记录，撤销会话时随会话整体失效。 */
public record StoredAccessToken(
        String tokenId,
        String sessionId,
        String username,
        Instant expiresAt
) {
}
