package com.github.h3yow.springbootidentitygatewayjava.auth.session;

import java.util.Set;

/**
 * 会话清单中的一条视图：仅包含当前有效会话，能力概要与会话实际权限判定保持一致。
 *
 * @param sessionId      会话（令牌族）标识
 * @param username       所属用户名
 * @param deviceType     设备类型
 * @param deviceName     设备名称
 * @param clientId       客户端标识
 * @param createdAt      会话建立时间（毫秒）
 * @param lastActiveAt   最近一次访问/续期时间（毫秒）
 * @param expiresAt      会话（刷新令牌）到期时间（毫秒）
 * @param roles          该会话实际可用角色概要
 * @param permissions    该会话实际可用权限概要
 * @param scopes         该会话实际可用范围概要
 */
public record SessionInfo(String sessionId, String username,
                          String deviceType, String deviceName, String clientId,
                          long createdAt, long lastActiveAt, long expiresAt,
                          Set<String> roles, Set<String> permissions, Set<String> scopes) {
}
