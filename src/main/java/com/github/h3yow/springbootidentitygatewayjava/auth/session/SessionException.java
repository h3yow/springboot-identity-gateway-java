package com.github.h3yow.springbootidentitygatewayjava.auth.session;

/**
 * 会话管理相关失败异常，携带可区分原因。
 */
public class SessionException extends RuntimeException {

    private final SessionFailureReason reason;

    public SessionException(SessionFailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public SessionFailureReason getReason() {
        return reason;
    }
}
