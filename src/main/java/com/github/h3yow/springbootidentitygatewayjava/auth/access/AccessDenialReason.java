package com.github.h3yow.springbootidentitygatewayjava.auth.access;

/**
 * 访问控制的可区分结论。
 */
public enum AccessDenialReason {
    /** 未认证：缺失/无效令牌。 */
    UNAUTHENTICATED,
    /** 已认证但无权限：角色与权限均不满足。 */
    FORBIDDEN_NO_PERMISSION,
    /** 令牌范围不足以覆盖目标范围。 */
    FORBIDDEN_INSUFFICIENT_SCOPE,
    /** 未标注保护要求，按默认拒绝处理。 */
    DEFAULT_DENY
}
