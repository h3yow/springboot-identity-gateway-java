package com.github.h3yow.springbootidentitygatewayjava.auth.access;

import com.github.h3yow.springbootidentitygatewayjava.auth.token.AccessTokenClaims;

/**
 * 访问判定结果：允许时携带令牌声明，拒绝时携带原因与判定依据说明。
 */
public record AccessDecision(boolean allowed, AccessTokenClaims claims,
                             AccessDenialReason denialReason, String rationale) {

    public static AccessDecision permit(AccessTokenClaims claims, String rationale) {
        return new AccessDecision(true, claims, null, rationale);
    }

    public static AccessDecision deny(AccessDenialReason reason, String rationale) {
        return new AccessDecision(false, null, reason, rationale);
    }
}
