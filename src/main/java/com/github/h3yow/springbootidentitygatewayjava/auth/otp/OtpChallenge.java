package com.github.h3yow.springbootidentitygatewayjava.auth.otp;

/**
 * 一次性验证码挑战（仅保存验证码哈希，不保存明文）。
 */
public record OtpChallenge(String username, String codeHash, long expiresAt, boolean consumed, long issuedAt) {

    /** 返回标记为已消费的新实例。 */
    public OtpChallenge asConsumed() {
        return new OtpChallenge(username, codeHash, expiresAt, true, issuedAt);
    }
}
