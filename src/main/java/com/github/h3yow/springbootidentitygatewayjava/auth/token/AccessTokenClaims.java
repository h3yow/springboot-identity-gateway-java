package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import java.util.Set;

/**
 * 访问令牌载荷。
 */
public record AccessTokenClaims(String jti, String familyId, String username,
                                Set<String> roles, Set<String> permissions, Set<String> scopes,
                                long issuedAt, long expiresAt) {
}
