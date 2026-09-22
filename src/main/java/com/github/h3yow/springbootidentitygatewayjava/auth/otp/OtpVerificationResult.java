package com.github.h3yow.springbootidentitygatewayjava.auth.otp;

/**
 * OTP 校验结论类型，供登录流程映射为可区分的失败原因。
 */
public enum OtpVerificationResult {
    OK,
    NO_CHALLENGE,
    EXPIRED,
    REUSED,
    MISMATCH
}
