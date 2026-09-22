package com.github.h3yow.springbootidentitygatewayjava.support;

import java.time.Instant;

/** 测试用可控时钟：初始固定时间，可手动推进，不依赖线程睡眠或真实等待。 */
public class MutableTimeProvider implements TimeProvider {

    private Instant current;

    public MutableTimeProvider(Instant start) {
        this.current = start;
    }

    @Override
    public Instant now() {
        return current;
    }

    public void advanceSeconds(long seconds) {
        this.current = current.plusSeconds(seconds);
    }
}
