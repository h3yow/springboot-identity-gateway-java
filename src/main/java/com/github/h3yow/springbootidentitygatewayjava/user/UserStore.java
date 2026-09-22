package com.github.h3yow.springbootidentitygatewayjava.user;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.model.AppUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** 内存用户库，启动时由配置种子用户构建，测试可直接注册自定义用户。 */
@Component
public class UserStore {

    private static final Logger log = LoggerFactory.getLogger(UserStore.class);
    private static final String PLAIN_PREFIX = "plain:";

    private final ConcurrentHashMap<String, AppUser> users = new ConcurrentHashMap<>();
    private final AuthProperties properties;
    private final PasswordEncoder passwordEncoder;

    public UserStore(AuthProperties properties, PasswordEncoder passwordEncoder) {
        this.properties = properties;
        this.passwordEncoder = passwordEncoder;
        loadSeedUsers();
    }

    private void loadSeedUsers() {
        for (AuthProperties.SeedUser seed : properties.getUsers()) {
            String configured = seed.getPassword();
            String hash;
            if (configured != null && configured.startsWith(PLAIN_PREFIX)) {
                if (!properties.isDevPlaintextPasswords()) {
                    throw new IllegalStateException(
                            "明文密码仅在 auth.dev-plaintext-passwords=true 时允许: " + seed.getUsername());
                }
                hash = passwordEncoder.encode(configured.substring(PLAIN_PREFIX.length()));
            } else {
                hash = configured;
            }
            AppUser user = new AppUser(seed.getUsername(), hash,
                    Set.copyOf(seed.getRoles()), Set.copyOf(seed.getScopes()));
            users.put(user.username(), user);
            log.info("加载种子用户: username={}, roles={}, scopes={}",
                    user.username(), user.roles(), user.scopes());
        }
    }

    public Optional<AppUser> find(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(username));
    }

    /** 测试/本地使用：以明文口令注册用户并存为哈希。 */
    public void register(String username, String rawPassword, Set<String> roles, Set<String> scopes) {
        AppUser user = new AppUser(username, passwordEncoder.encode(rawPassword),
                Set.copyOf(roles == null ? new HashSet<>() : roles),
                Set.copyOf(scopes == null ? new HashSet<>() : scopes));
        users.put(username, user);
    }
}
