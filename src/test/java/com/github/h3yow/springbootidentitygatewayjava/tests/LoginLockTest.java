package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.LoginFailureTracker;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.support.MutableTimeProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 连续失败锁定与窗口到期自动恢复。
 * 全程使用固定时钟 + 手动推进，时间判定可稳定复现，不依赖真实等待。
 */
class LoginLockTest {

    private static final Logger log = LoggerFactory.getLogger(LoginLockTest.class);
    private static final Instant T0 = Instant.parse("2026-09-23T00:00:00Z");

    private AuthProperties props(int maxFailures, long lockSeconds) {
        AuthProperties p = new AuthProperties();
        p.setMaxFailures(maxFailures);
        p.setLockSeconds(lockSeconds);
        return p;
    }

    @Test
    void locksAfterThresholdAndAutoRecoversAfterWindow() {
        MutableTimeProvider clock = new MutableTimeProvider(T0);
        AuthProperties props = props(3, 300);
        LoginFailureTracker tracker = new LoginFailureTracker(props, clock);
        String user = "alice";

        for (int i = 1; i <= 2; i++) {
            tracker.recordFailure(user);
            log.info("[输入] 第 {} 次失败 @now={} [判定依据] count<{} 未锁定, isLocked={}",
                    i, clock.now(), props.getMaxFailures(), tracker.isLocked(user));
            assertFalse(tracker.isLocked(user), "未达阈值不应锁定");
        }

        Instant lockedUntil = tracker.recordFailure(user);
        assertNotNull(lockedUntil, "达到阈值应返回锁定到期时刻");
        log.info("[输入] 第 3 次失败 @now={} [判定依据] count>={} 锁定至 {}",
                clock.now(), props.getMaxFailures(), lockedUntil);
        assertTrue(tracker.isLocked(user), "达到阈值应立即锁定");

        // 窗口内推进 299 秒仍锁定
        clock.advanceSeconds(299);
        log.info("[输入] 推进至 {} (距锁定 {}s, 窗口 300s) [判定依据] now<lockedUntil -> 仍锁定",
                clock.now(), 299);
        assertTrue(tracker.isLocked(user), "窗口内仍应锁定");

        // 跨过窗口 1 秒，惰性恢复
        clock.advanceSeconds(1);
        boolean locked = tracker.isLocked(user);
        log.info("[输入] 推进至 {} (距锁定 300s) [判定依据] now>=lockedUntil -> 惰性清空计数, isLocked={}",
                clock.now(), locked);
        assertFalse(locked, "窗口到期应自动恢复为可登录");
    }

    @Test
    void successfulLoginResetsCounter() {
        MutableTimeProvider clock = new MutableTimeProvider(T0);
        AuthProperties props = props(2, 300);
        LoginFailureTracker tracker = new LoginFailureTracker(props, clock);

        tracker.recordFailure("bob");
        tracker.reset("bob");
        log.info("[输入] 1 次失败后成功登录并 reset @now={} [判定依据] 计数归零，再次单次失败不应触发锁定",
                clock.now());
        tracker.recordFailure("bob");
        assertFalse(tracker.isLocked("bob"), "成功登录后计数应被重置");
    }
}
