package com.github.h3yow.springbootidentitygatewayjava.auth.credential;

/**
 * 密码哈希/校验抽象（PBKDF2WithHmacSHA256）。
 */
public interface PasswordHasher {
    /** 生成 salt:iterations:hash 形式的存储串。 */
    String hash(String rawPassword);

    /** 校验明文密码与存储串是否匹配。 */
    boolean matches(String rawPassword, String stored);
}
