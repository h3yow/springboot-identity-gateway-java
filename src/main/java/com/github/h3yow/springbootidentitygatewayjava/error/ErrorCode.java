package com.github.h3yow.springbootidentitygatewayjava.error;

import org.springframework.http.HttpStatus;

/**
 * 可区分的失败原因。每一类异常路径都有独立错误码，
 * 调用方与测试可据此判定拒绝原因，而非仅依赖 HTTP 状态码。
 */
public enum ErrorCode {

    // ---- 登录阶段 ----
    LOGIN_BAD_CREDENTIALS(HttpStatus.UNAUTHORIZED),
    LOGIN_ACCOUNT_LOCKED(HttpStatus.LOCKED),
    OTP_REQUIRED(HttpStatus.UNAUTHORIZED),
    OTP_INVALID(HttpStatus.UNAUTHORIZED),
    OTP_EXPIRED(HttpStatus.UNAUTHORIZED),
    OTP_REPLAYED(HttpStatus.CONFLICT),
    PENDING_LOGIN_NOT_FOUND(HttpStatus.UNAUTHORIZED),

    // ---- 令牌阶段 ----
    TOKEN_MISSING(HttpStatus.UNAUTHORIZED),
    TOKEN_MALFORMED(HttpStatus.UNAUTHORIZED),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED),
    TOKEN_REVOKED(HttpStatus.UNAUTHORIZED),
    TOKEN_WRONG_TYPE(HttpStatus.UNAUTHORIZED),
    REFRESH_REPLAYED(HttpStatus.UNAUTHORIZED),
    SESSION_REVOKED(HttpStatus.UNAUTHORIZED),

    // ---- 授权阶段 ----
    ACCESS_DENIED_ROLE(HttpStatus.FORBIDDEN),
    ACCESS_DENIED_SCOPE(HttpStatus.FORBIDDEN),

    // ---- 通用 ----
    INVALID_REQUEST(HttpStatus.BAD_REQUEST);

    private final HttpStatus httpStatus;

    ErrorCode(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public HttpStatus httpStatus() {
        return httpStatus;
    }
}
