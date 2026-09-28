package com.github.h3yow.springbootidentitygatewayjava.auth.session;

/**
 * 会话管理操作失败：找不到会话或会话不属于当前用户（统一结论，避免会话枚举）。
 */
public class SessionException extends RuntimeException {

    public SessionException(String message) {
        super(message);
    }
}
