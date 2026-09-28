package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * 令牌服务端状态存储：刷新令牌记录与令牌族（会话）。
 *
 * <p>两层加锁：
 * <ul>
 *   <li><b>族锁</b>（{@code familyLocks}）：同一族“判定 + 状态变更”串行，保证一次性轮换、
 *       撤销/续期竞争、淘汰/续期竞争的读改写原子性。</li>
 *   <li><b>用户锁</b>（{@code userLocks}）：同一账号的登录建会话串行，保证容量上限检查与
 *       淘汰选择在并发登录下不多不少。</li>
 * </ul>
 * 加锁顺序固定为“用户锁 -&gt; 族锁”，全代码库不存在反向获取，避免死锁。
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

    /** 列出某用户名下的全部族（含已终态的，由调用方按状态/过期过滤）。 */
    public List<TokenFamily> familiesOf(String username) {
        List<TokenFamily> result = new ArrayList<>();
        for (TokenFamily family : families.values()) {
            if (username.equals(family.username())) {
                result.add(family);
            }
        }
        return result;
    }

    /** 原子保存新刷新令牌（须在持有对应族锁时调用）。 */
    public void saveRefreshToken(StoredRefreshToken token) {
        refreshTokens.put(token.tokenHash(), token);
    }

    /** 撤销整个令牌族（须在持有对应族锁时调用）；幂等，重复调用结论一致。 */
    public void revokeFamily(String familyId) {
        families.computeIfPresent(familyId, (id, family) -> asState(family, SessionState.REVOKED));
    }

    /** 仅当族仍处于 ACTIVE 时将其淘汰为 EVICTED；已是终态则保持不变。返回是否发生了淘汰。 */
    public boolean markEvicted(String familyId) {
        boolean[] changed = {false};
        families.computeIfPresent(familyId, (id, family) -> {
            if (family.state() == SessionState.ACTIVE) {
                changed[0] = true;
                return asState(family, SessionState.EVICTED);
            }
            return family;
        });
        return changed[0];
    }

    /** 重放检测：将仍 ACTIVE 的族标记为 REPLAY_REVOKED；其它终态保持不变。 */
    public void markReplayRevoked(String familyId) {
        families.computeIfPresent(familyId, (id, family) ->
                family.state() == SessionState.ACTIVE ? asState(family, SessionState.REPLAY_REVOKED) : family);
    }

    /** 更新仍 ACTIVE 族的最近活跃时间（访问/成功续期时调用）；终态族不受影响。 */
    public void touchLastActive(String familyId, long now) {
        families.computeIfPresent(familyId, (id, family) ->
                family.state() == SessionState.ACTIVE
                        ? new TokenFamily(family.familyId(), family.username(), family.createdAt(), false,
                                family.deviceId(), family.deviceName(), family.clientId(), now,
                                family.roles(), family.permissions(), family.scopes(), SessionState.ACTIVE)
                        : family);
    }

    /** 在族锁内执行一次原子操作：用于一次性轮换、撤销、淘汰与族状态的读改写组合。 */
    public <T> T withFamilyLock(String familyId, Function<String, T> action) {
        Object lock = familyLocks.computeIfAbsent(familyId, id -> new Object());
        synchronized (lock) {
            return action.apply(familyId);
        }
    }

    /** 在用户锁内执行一次原子操作：用于登录时的容量检查 + 淘汰 + 新建会话。 */
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

    private static TokenFamily asState(TokenFamily family, SessionState state) {
        return new TokenFamily(family.familyId(), family.username(), family.createdAt(), true,
                family.deviceId(), family.deviceName(), family.clientId(), family.lastActiveAt(),
                family.roles(), family.permissions(), family.scopes(), state);
    }
}
