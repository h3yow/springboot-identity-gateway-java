package com.github.h3yow.springbootidentitygatewayjava.time;

/**
 * 时间源抽象，便于测试中固定/推进时间，避免依赖系统时钟。
 */
public interface Clock {
    /** 当前时间（毫秒）。 */
    long nowMillis();
}
