package com.github.h3yow.springbootidentitygatewayjava.auth.domain;

import java.util.Set;

/**
 * 用户账户（内存存储的演示模型）。
 *
 * @param scopes 登录后签发访问令牌时携带的权限范围上限
 */
public record UserAccount(String username, String passwordHash,
                          Set<String> roles, Set<String> permissions, Set<String> scopes) {
}
