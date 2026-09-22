package com.github.h3yow.springbootidentitygatewayjava.error;

import java.time.Instant;

/** 统一错误响应体：错误码 + 可解释信息 + 发生时间。 */
public record ApiError(
        String code,
        String message,
        Instant timestamp
) {
}
