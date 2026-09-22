package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 令牌相关失败异常，携带可区分原因。
 */
public class TokenException extends RuntimeException {

    private final TokenRejectionReason reason;

    public TokenException(TokenRejectionReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public TokenRejectionReason getReason() {
        return reason;
    }
}
