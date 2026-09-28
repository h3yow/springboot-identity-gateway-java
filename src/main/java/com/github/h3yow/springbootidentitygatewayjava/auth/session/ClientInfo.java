package com.github.h3yow.springbootidentitygatewayjava.auth.session;

/**
 * 会话的客户端画像：区分是哪台设备、哪个客户端登录。
 *
 * @param deviceType 设备类型，如 phone / laptop / tablet（可为空）
 * @param deviceName 设备名称，如“iPhone 15 / 家里的电脑”（可为空）
 * @param clientId   客户端标识，如 ios-app / web-browser（可为空）
 */
public record ClientInfo(String deviceType, String deviceName, String clientId) {

    /** 未提供任何画像信息时的默认值。 */
    public static ClientInfo unknown() {
        return new ClientInfo(null, null, null);
    }
}
