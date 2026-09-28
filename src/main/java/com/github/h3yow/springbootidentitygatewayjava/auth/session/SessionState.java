package com.github.h3yow.springbootidentitygatewayjava.auth.session;

/**
 * 会话终止状态，用于区分“用户主动撤销”“容量淘汰”与“自然过期”。
 */
public enum SessionState {
    ACTIVE,
    REVOKED,
    EVICTED
}
