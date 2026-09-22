package com.github.h3yow.springbootidentitygatewayjava.support;

import java.time.Instant;

/**
 * 时间来源抽象。生产环境使用系统时钟，测试环境可替换为可控时钟，
 * 使过期与锁定相关的时间判定可稳定复现，不依赖真实流逝。
 */
public interface TimeProvider {

    Instant now();
}
