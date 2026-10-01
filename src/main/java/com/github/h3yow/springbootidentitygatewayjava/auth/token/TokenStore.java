package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionState;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 令牌服务端状态存储：刷新令牌记录与令牌族。
 *
 * <p>两级锁：
 * <ul>
 *   <li>族锁（familyLocks）：串行化同一会话内的轮换/撤销/淘汰判定</li>
 *   <li>用户锁（userLocks）：串行化同一账号的“登录建会话 + 容量淘汰”，
 *       保证并发登录绝不超过 {@code auth.max-sessions-per-user}，
 *       且淘汰只选最久未活跃的旧会话，不会误伤新会话</li>
 * </ul>
 * 加锁顺序固定为：先用户锁、后族锁，避免锁顺序反转导致的死锁。
 */
@Component
public class TokenStore {

    private final Map<String, TokenFamily> families = new ConcurrentHashMap<>();
    private final Map<String, StoredRefreshToken> refreshTokens = new ConcurrentHashMap<>();
    private final Map<String, Object> familyLocks = new ConcurrentHashMap<>();
    private final Map<String, Object> userLocks = new ConcurrentHashMap<>();

    /** 保存族。 */
    public void saveFamily(TokenFamily family) {
        families.put(family.familyId(), family);
        familyLocks.computeIfAbsent(family.familyId(), id -> new Object());
        userLocks.computeIfAbsent(family.username(), id -> new Object());
    }

    /** 按刷新令牌哈希查找记录。 */
    public Optional<StoredRefreshToken> findRefreshToken(String tokenHash) {
        return Optional.ofNullable(refreshTokens.get(tokenHash));
    }

    /** 按 id 查找族。 */
    public Optional<TokenFamily> findFamily(String familyId) {
        return Optional.ofNullable(families.get(familyId));
    }

    /** 返回当前全部族的快照（清单/容量扫描用）。 */
    public List<TokenFamily> allFamilies() {
        return new ArrayList<>(families.values());
    }

    /** 原子保存新刷新令牌（须在持有对应族锁时调用）。 */
    public void saveRefreshToken(StoredRefreshToken token) {
        refreshTokens.put(token.tokenHash(), token);
    }

    /** 撤销整个令牌族（须在持有对应族锁时调用）。 */
    public void revokeFamily(String familyId) {
        families.computeIfPresent(familyId, (id, family) -> family.asRevoked());
    }

    /** 将整个令牌族标记为容量淘汰（须在持有对应族锁或用户锁时调用）。 */
    public void evictFamily(String familyId) {
        families.computeIfPresent(familyId, (id, family) -> family.asEvicted());
    }

    /**
     * 直接保存一个更新后的族（须在持有族锁或用户锁时调用，用于滑动续期/淘汰写入）。
     *
     * <p>状态单调保护：会话终态（REVOKED / EVICTED）一旦写入，绝不允许被一个携带
     * ACTIVE 的旧快照覆盖回去（防止“撤销/淘汰已生效、又被并发的读-改-写写活”的丢失更新）。
     * 同态或在终态之间合法的原样写入（如终态先到先得保持不变）照常放行。
     */
    public void putFamily(TokenFamily family) {
        families.compute(family.familyId(), (id, existing) -> {
            if (existing != null && existing.terminated() && family.active()) {
                return existing;
            }
            return family;
        });
    }

    /**
     * 仅当族当前仍为 ACTIVE 时，原子地更新其最近活跃时间/到期时间。
     *
     * <p>用 {@code compute} 读改写一次完成，因此即使调用方不持有族锁（访问路径更新
     * LRU 活跃时间），也绝不会把一个已 REVOKED / EVICTED 的族用旧 ACTIVE 快照覆盖活。
     *
     * @return 更新后的最新族；若族不存在或已不在 ACTIVE 态，则返回存储中的当前值（可能为空）
     */
    public Optional<TokenFamily> touchIfActive(String familyId, long newLastActiveAt, long newExpiresAt) {
        return Optional.ofNullable(families.compute(familyId, (id, existing) -> {
            if (existing != null && existing.state() == SessionState.ACTIVE) {
                return existing.touch(newLastActiveAt, newExpiresAt);
            }
            return existing;
        }));
    }

    /**
     * 在族锁内执行一次原子操作：用于一次性轮换与族撤销的读改写组合。
     */
    public <T> T withFamilyLock(String familyId, Function<String, T> action) {
        Object lock = familyLocks.computeIfAbsent(familyId, id -> new Object());
        synchronized (lock) {
            return action.apply(familyId);
        }
    }

    /**
     * 在用户锁内执行一次原子操作：用于登录建会话时的容量判定与 LRU 淘汰。
     * 需要在其中改动某个族时，应先取用户锁、再取对应族锁（固定锁序）。
     */
    public <T> T withUserLock(String username, Function<String, T> action) {
        Object lock = userLocks.computeIfAbsent(username, id -> new Object());
        synchronized (lock) {
            return action.apply(username);
        }
    }

    /** 清空全部族与刷新令牌记录（测试隔离用）。 */
    public void clear() {
        families.clear();
        refreshTokens.clear();
        familyLocks.clear();
        userLocks.clear();
    }
}
