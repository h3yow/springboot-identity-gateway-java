package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 令牌被拒绝/刷新失败的可区分原因。
 */
public enum TokenRejectionReason {
    MALFORMED,
    BAD_SIGNATURE,
    EXPIRED,
    REVOKED,
    ROTATED,
    UNKNOWN,
    WRONG_TYPE
}
