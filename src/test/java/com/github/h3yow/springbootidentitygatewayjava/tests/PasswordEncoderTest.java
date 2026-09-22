package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.user.PasswordEncoder;
import com.github.h3yow.springbootidentitygatewayjava.user.Pbkdf2PasswordEncoder;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 口令编码自洽性、盐随机性与错误口令拒绝；不涉及真实凭据。 */
class PasswordEncoderTest {

    private static final Logger log = LoggerFactory.getLogger(PasswordEncoderTest.class);
    private final PasswordEncoder encoder = new Pbkdf2PasswordEncoder();

    @Test
    void encodesAndVerifiesConsistently() {
        String raw = "demo-password-123";
        String h1 = encoder.encode(raw);
        String h2 = encoder.encode(raw);
        log.info("[输入] raw='{}' -> h1='{}', h2='{}' [判定依据] 相同口令因随机盐产生不同哈希，但都应校验通过",
                raw, h1, h2);
        assertNotEquals(h1, h2, "随机盐应使两次编码结果不同");
        assertTrue(encoder.matches(raw, h1));
        assertTrue(encoder.matches(raw, h2));
    }

    @Test
    void rejectsWrongPasswordAndMalformedHash() {
        String hash = encoder.encode("correct-horse");
        log.info("[输入] 正确口令='correct-horse', 待验='battery-staple', 哈希格式='{}' [判定依据] PBKDF2 重算比对不等",
                hash.substring(0, 12) + "…");
        assertFalse(encoder.matches("battery-staple", hash));
        assertFalse(encoder.matches("correct-horse", "not-a-valid-hash"));
        assertFalse(encoder.matches("correct-horse", null));
    }
}
