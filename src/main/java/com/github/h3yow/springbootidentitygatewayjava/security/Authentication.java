package com.github.h3yow.springbootidentitygatewayjava.security;

import java.util.Set;

/** 通过令牌校验后建立的请求认证主体。 */
public record Authentication(
        String username,
        String sessionId,
        Set<String> roles,
        Set<String> scopes
) {
}
