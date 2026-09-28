package com.github.h3yow.springbootidentitygatewayjava.auth.session;

import java.util.Set;

/**
 * 会话清单中的单条视图：设备/客户端、建立与最近活跃时间、当前实际能力概要。
 */
public record SessionInfo(String sessionId,
                          String deviceId,
                          String deviceName,
                          String clientId,
                          long createdAt,
                          long lastActiveAt,
                          long expiresAt,
                          Set<String> roles,
                          Set<String> permissions,
                          Set<String> scopes) {
}
