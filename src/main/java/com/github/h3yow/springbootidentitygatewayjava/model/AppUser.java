package com.github.h3yow.springbootidentitygatewayjava.model;

import java.util.Set;

/** 已注册用户：含口令哈希、角色集合与权限范围集合。 */
public final class AppUser {

    private final String username;
    private final String passwordHash;
    private final Set<String> roles;
    private final Set<String> scopes;

    public AppUser(String username, String passwordHash, Set<String> roles, Set<String> scopes) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = roles;
        this.scopes = scopes;
    }

    public String username() {
        return username;
    }

    public String passwordHash() {
        return passwordHash;
    }

    public Set<String> roles() {
        return roles;
    }

    public Set<String> scopes() {
        return scopes;
    }
}
