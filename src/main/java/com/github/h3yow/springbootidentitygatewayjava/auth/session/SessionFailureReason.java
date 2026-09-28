package com.github.h3yow.springbootidentitygatewayjava.auth.session;

/**
 * 会话管理操作（清单/精准撤销）被拒绝的可区分原因。
 */
public enum SessionFailureReason {
    SESSION_NOT_FOUND,
    SESSION_NOT_OWNED
}
