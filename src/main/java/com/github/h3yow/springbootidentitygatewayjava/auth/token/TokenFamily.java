package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import com.github.h3yow.springbootidentitygatewayjava.auth.session.ClientInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionState;

import java.util.Set;

/**
 * 刷新令牌族：一次登录会话对应一个族；族进入终止态后该会话下所有令牌失效。
 *
 * <p>多端会话管理在族上扩展了：
 * <ul>
 *   <li>{@link #state}：ACTIVE / REVOKED（用户主动撤销）/ EVICTED（容量上限淘汰），终态可区分</li>
 *   <li>{@link #clientInfo}：设备与客户端画像</li>
 *   <li>{@link #roles} / {@link #permissions} / {@link #scopes}：会话已授予能力的服务端快照，
 *       续期后据此重新签发，保证能力不丢失</li>
 *   <li>{@link #lastActiveAt}：最近一次访问/续期时间（LRU 淘汰依据）</li>
 *   <li>{@link #expiresAt}：会话（刷新令牌）到期时间，续期后滑动</li>
 * </ul>
 */
public record TokenFamily(String familyId, String username, long createdAt, long lastActiveAt,
                          long expiresAt, SessionState state, ClientInfo clientInfo,
                          Set<String> roles, Set<String> permissions, Set<String> scopes) {

    /** 兼容旧调用的精简构造：无画像、无能力快照、无显式到期。 */
    public TokenFamily(String familyId, String username, long createdAt, boolean revoked) {
        this(familyId, username, createdAt, createdAt, 0L,
                revoked ? SessionState.REVOKED : SessionState.ACTIVE,
                ClientInfo.unknown(), Set.of(), Set.of(), Set.of());
    }

    /** 规范构造：对集合做防御性不可变拷贝。 */
    public TokenFamily {
        roles = roles == null ? Set.of() : Set.copyOf(roles);
        permissions = permissions == null ? Set.of() : Set.copyOf(permissions);
        scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        clientInfo = clientInfo == null ? ClientInfo.unknown() : clientInfo;
        state = state == null ? SessionState.ACTIVE : state;
    }

    /** 是否被用户主动撤销（不含容量淘汰）。 */
    public boolean revoked() {
        return state == SessionState.REVOKED;
    }

    /** 是否已进入任一终止态（撤销或淘汰）。 */
    public boolean terminated() {
        return state != SessionState.ACTIVE;
    }

    public boolean active() {
        return state == SessionState.ACTIVE;
    }

    /**
     * 标记为用户主动撤销。终态“先到先得”：已被淘汰的会话不因后续操作被改写成撤销。
     */
    public TokenFamily asRevoked() {
        if (state != SessionState.ACTIVE) {
            return this;
        }
        return new TokenFamily(familyId, username, createdAt, lastActiveAt, expiresAt,
                SessionState.REVOKED, clientInfo, roles, permissions, scopes);
    }

    /**
     * 标记为容量上限淘汰。仅 ACTIVE 可转移；撤销态保持撤销。
     */
    public TokenFamily asEvicted() {
        if (state != SessionState.ACTIVE) {
            return this;
        }
        return new TokenFamily(familyId, username, createdAt, lastActiveAt, expiresAt,
                SessionState.EVICTED, clientInfo, roles, permissions, scopes);
    }

    /** 更新最近活跃时间与会话到期时间（滑动续期），其余不变。 */
    public TokenFamily touch(long newLastActiveAt, long newExpiresAt) {
        return new TokenFamily(familyId, username, createdAt, newLastActiveAt, newExpiresAt,
                state, clientInfo, roles, permissions, scopes);
    }
}
