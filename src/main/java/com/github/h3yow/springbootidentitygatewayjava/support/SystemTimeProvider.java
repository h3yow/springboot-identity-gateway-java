package com.github.h3yow.springbootidentitygatewayjava.support;

import org.springframework.stereotype.Component;

import java.time.Instant;

/** 基于系统 UTC 时间的默认实现。 */
@Component
public class SystemTimeProvider implements TimeProvider {

    @Override
    public Instant now() {
        return Instant.now();
    }
}
