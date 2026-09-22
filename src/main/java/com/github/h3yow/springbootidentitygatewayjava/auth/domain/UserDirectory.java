package com.github.h3yow.springbootidentitygatewayjava.auth.domain;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.PasswordHasher;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 内存用户目录；启动时播种三个演示账户，覆盖不同角色/权限/范围边界：
 * <ul>
 *   <li>alice / password-alice：普通用户，user:read 权限，含 reports:read 范围</li>
 *   <li>bob / password-bob：普通用户，user:read 权限，不含 reports:read 范围</li>
 *   <li>admin / password-admin：管理员，拥有全部权限与范围</li>
 * </ul>
 * 密码仅用于本地演示，不依赖任何外部用户服务。
 */
@Component
public class UserDirectory {

    private final Map<String, UserAccount> accounts = new LinkedHashMap<>();

    public UserDirectory(PasswordHasher passwordHasher) {
        seed(passwordHasher, "alice", "password-alice",
                Set.of("user"), Set.of("user:read"), Set.of("openid", "reports:read"));
        seed(passwordHasher, "bob", "password-bob",
                Set.of("user"), Set.of("user:read"), Set.of("openid"));
        seed(passwordHasher, "admin", "password-admin",
                Set.of("admin", "user"), Set.of("user:read", "user:write"),
                Set.of("openid", "reports:read"));
    }

    private void seed(PasswordHasher passwordHasher, String username, String rawPassword,
                      Set<String> roles, Set<String> permissions, Set<String> scopes) {
        accounts.put(username, new UserAccount(username, passwordHasher.hash(rawPassword), roles, permissions, scopes));
    }

    /** 按用户名查找账户。 */
    public Optional<UserAccount> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(accounts.get(username));
    }
}
