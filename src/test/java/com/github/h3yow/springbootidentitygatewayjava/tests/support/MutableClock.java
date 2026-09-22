package com.github.h3yow.springbootidentitygatewayjava.tests.support;

import com.github.h3yow.springbootidentitygatewayjava.time.Clock;

/**
 * 测试用可控时钟：时间可固定、可手动推进，确保过期/锁定判定稳定复现，不依赖墙钟。
 */
public class MutableClock implements Clock {

    private volatile long current;

    public MutableClock(long startMillis) {
        this.current = startMillis;
    }

    @Override
    public long nowMillis() {
        return current;
    }

    /** 将时钟向前推进毫秒数。 */
    public void advance(long deltaMillis) {
        if (deltaMillis < 0) {
            throw new IllegalArgumentException("不允许回拨时间");
        }
        this.current += deltaMillis;
    }

    /** 直接设置当前时间。 */
    public void setNow(long millis) {
        this.current = millis;
    }
}
