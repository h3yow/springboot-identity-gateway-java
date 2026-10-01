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

    /** 直接保存一个更新后的族（须在持有族锁或用户锁时调用，用于滑动续期/淘汰写入）。 */
    public void putFamily(TokenFamily family) {
        families.put(family.familyId(), family);
    }

    /**
     * 在族锁内对已存在的族做一次受状态机约束的条件更新（用于成功访问/续期的最近活跃回写）。
     *
     * <p>状态机护栏：当前族已进入终止态（REVOKED/EVICTED）时，拒绝任何会把它改回 ACTIVE 的写入，
     * 终态“先到先得”且不可逆，从存储层杜绝“撤销生效后又被旧快照写活”。仅当当前族仍为 ACTIVE 时，
     * 才应用更新函数。
     *
     * @return 当前最新族；若调用方据此判断已终止，应按 REVOKED/EVICTED 拒绝本次请求
     */
    public TokenFamily updateActiveFamily(String familyId,
                                          java.util.function.UnaryOperator<TokenFamily> update) {
        return families.compute(familyId, (id, current) -> {
            if (current == null) {
                return null;
            }
            if (current.state() != SessionState.ACTIVE) {
                // 已撤销/已淘汰：终态不可逆，保留当前快照，拒绝复活写入（不改建立/活跃时间等任何字段）
                return current;
            }
            TokenFamily updated = update.apply(current);
            if (updated.state() != SessionState.ACTIVE) {
                // 活跃回写路径只允许仍为 ACTIVE 的结果；任何意外的状态翻转都不接受
                throw new IllegalStateException("活跃会话回写不得改变终止状态: family=" + id);
            }
            return updated;
        });
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
