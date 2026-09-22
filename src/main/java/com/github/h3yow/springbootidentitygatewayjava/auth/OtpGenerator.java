package com.github.h3yow.springbootidentitygatewayjava.auth;

import java.security.SecureRandom;

/** 生成 6 位数字一次性验证码。 */
public final class OtpGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private OtpGenerator() {
    }

    public static String generate() {
        int value = RANDOM.nextInt(1_000_000);
        return String.format("%06d", value);
    }
}
