package com.github.h3yow.springbootidentitygatewayjava.auth.login;

/**
 * 登录失败异常，携带可区分原因。
 */
public class LoginException extends RuntimeException {

    private final LoginFailureReason reason;

    public LoginException(LoginFailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public LoginFailureReason getReason() {
        return reason;
    }
}
