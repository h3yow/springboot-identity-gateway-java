package com.github.h3yow.springbootidentitygatewayjava.auth.login;

/**
 * 登录被拒绝的可区分原因。
 */
public enum LoginFailureReason {
    BAD_CREDENTIALS,
    ACCOUNT_LOCKED,
    OTP_EXPIRED,
    OTP_REUSED,
    OTP_MISMATCH,
    OTP_MISSING
}
