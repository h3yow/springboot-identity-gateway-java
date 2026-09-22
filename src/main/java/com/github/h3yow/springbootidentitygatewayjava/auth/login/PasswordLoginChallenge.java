package com.github.h3yow.springbootidentitygatewayjava.auth.login;

/**
 * 第一步（密码）成功后的挑战上下文。
 */
public record PasswordLoginChallenge(String username) {
}
