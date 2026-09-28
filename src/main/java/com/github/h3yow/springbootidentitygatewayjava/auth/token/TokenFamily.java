package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import java.util.Set;

/**
 * 刷新令牌族（一次登录会话一个族）；族进入终态后该会话下所有令牌失效。
 *
 * <p>承载多端会话管理所需元数据：
 * <ul>
 *   <li>{@code deviceId/deviceName/clientId}：区分设备与客户端</li>
 *   <li>{@code lastActiveAt}：最近一次访问或成功续期时间，用于容量淘汰时挑选最久未活跃会话</li>
 *   <li>{@code roles/permissions/scopes}：登录时能力快照，续期后保持不变，作为清单概要与权限判定的唯一来源</li>
 *   <li>{@code state}：ACTIVE / REVOKED / EVICTED / REPLAY_REVOKED</li>
 * </ul>
 */
public record TokenFamily(String familyId,
                          String username,
                          long createdAt,
                          boolean revoked,
                          String deviceId,
                          String deviceName,
                          String clientId,
                          long lastActiveAt,
                          Set<String> roles,
                          Set<String> permissions,
                          Set<String> scopes,
                          SessionState state) {

    /** 兼容既有调用的最小构造（骨架阶段使用，后续由签发路径填充完整元数据）。 */
    public TokenFamily(String familyId, String username, long createdAt, boolean revoked) {
        this(familyId, username, createdAt, revoked,
                "UNKNOWN-DEVICE", "", "UNKNOWN-CLIENT",
                createdAt, Set.of(), Set.of(), Set.of(),
                revoked ? SessionState.REVOKED : SessionState.ACTIVE);
    }

    /** 返回已主动撤销的新实例（撤销为终态，淘汰不会覆盖用户主动撤销）。 */
    public TokenFamily asRevoked() {
        return new TokenFamily(familyId, username, createdAt, true,
                deviceId, deviceName, clientId, lastActiveAt,
                roles, permissions, scopes, SessionState.REVOKED);
    }
}
