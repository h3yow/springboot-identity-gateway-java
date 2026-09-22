package com.github.h3yow.springbootidentitygatewayjava.web.dto;

/**
 * 统一错误响应体。
 */
public record ApiError(String error, String reason, String message) {
}
