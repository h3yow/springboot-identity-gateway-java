package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 令牌服务端状态存储：刷新令牌记录与令牌族。
 * 所有“判定 + 状态变更”操作以族为粒度加锁（familyLocks 中每个族一把锁），
 * 保证同一个刷新令牌在并发/重复使用下只有一次轮换成功。
 */
@Component
public class TokenStore {

    private final Map<String, TokenFamily> families = new ConcurrentHashMap<>();
    private final Map<String, StoredRefreshToken> refreshTokens = new ConcurrentHashMap<>();
    private final Map<String, Object> familyLocks = new ConcurrentHashMap<>();

    /** 保存族。 */
    public void saveFamily(TokenFamily family) {
        families.put(family.familyId(), family);
        familyLocks.computeIfAbsent(family.familyId(), id -> new Object());
    }

    /** 按刷新令牌哈希查找记录。 */
    public Optional<StoredRefreshToken> findRefreshToken(String tokenHash) {
        return Optional.ofNullable(refreshTokens.get(tokenHash));
    }

    /** 按 id 查找族。 */
    public Optional<TokenFamily> findFamily(String familyId) {
        return Optional.ofNullable(families.get(familyId));
    }

    /** 原子保存新刷新令牌（须在持有对应族锁时调用）。 */
    public void saveRefreshToken(StoredRefreshToken token) {
        refreshTokens.put(token.tokenHash(), token);
    }

    /** 撤销整个令牌族（须在持有对应族锁时调用）。 */
    public void revokeFamily(String familyId) {
        families.computeIfPresent(familyId, (id, family) -> family.asRevoked());
    }

    /**
     * 在族锁内执行一次原子操作：用于一次性轮换与族撤销的读改写组合。
     */
    public <T> T withFamilyLock(String familyId, java.util.function.Function<String, T> action) {
        Object lock = familyLocks.computeIfAbsent(familyId, id -> new Object());
        synchronized (lock) {
            return action.apply(familyId);
        }
    }

    /** 清空全部族与刷新令牌记录（测试隔离用）。 */
    public void clear() {
        families.clear();
        refreshTokens.clear();
        familyLocks.clear();
    }
}
