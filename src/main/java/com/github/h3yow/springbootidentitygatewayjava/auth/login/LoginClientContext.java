package com.github.h3yow.springbootidentitygatewayjava.auth.login;

/**
 * 登录时客户端自报的设备/客户端信息，用于多端会话区分。
 *
 * @param deviceId   设备标识（可为空，空时以 UNKNOWN-DEVICE 兜底）
 * @param deviceName 设备可读名称（可为空）
 * @param clientId   客户端标识（可为空，空时以 UNKNOWN-CLIENT 兜底）
 */
public record LoginClientContext(String deviceId, String deviceName, String clientId) {

    /** 未携带客户端信息时的默认上下文。 */
    public static LoginClientContext unnamed() {
        return new LoginClientContext(null, null, null);
    }
}
