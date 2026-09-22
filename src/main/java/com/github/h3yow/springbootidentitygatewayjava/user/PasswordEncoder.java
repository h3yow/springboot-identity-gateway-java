package com.github.h3yow.springbootidentitygatewayjava.user;

/** 口令编码与校验抽象，默认使用 JDK 内置 PBKDF2WithHmacSHA256。 */
public interface PasswordEncoder {

    String encode(String raw);

    boolean matches(String raw, String encoded);
}
