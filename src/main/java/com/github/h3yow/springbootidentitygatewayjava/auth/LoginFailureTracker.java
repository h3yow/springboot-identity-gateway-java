package com.github.h3yow.springbootidentitygatewayjava.auth;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.support.TimeProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 按用户名跟踪连续失败次数与锁定到期时刻。
 * 锁定采用惰性恢复：窗口到期后下一次访问自动清空计数，无需后台任务。
 */
@Component
public class LoginFailureTracker {

    private static final Logger log = LoggerFactory.getLogger(LoginFailureTracker.class);

    private record FailureState(int count, Instant lockedUntil) {
    }

    private final ConcurrentHashMap<String, FailureState> states = new ConcurrentHashMap<>();
    private final AuthProperties properties;
    private final TimeProvider timeProvider;

    public LoginFailureTracker(AuthProperties properties, TimeProvider timeProvider) {
        this.properties = properties;
        this.timeProvider = timeProvider;
    }

    /** 当前是否处于锁定窗口内；窗口到期自动恢复（清除计数）。 */
    public boolean isLocked(String username) {
        FailureState state = states.get(username);
        if (state == null || state.lockedUntil() == null) {
            return false;
        }
        if (!timeProvider.now().isBefore(state.lockedUntil())) {
            // 窗口到期：自动恢复，清空计数，后续请求视为未锁定
            states.remove(username, state);
            log.info("锁定窗口到期，自动恢复: username={}, lockedUntil={}, now={}",
                    username, state.lockedUntil(), timeProvider.now());
            return false;
        }
        return true;
    }

    /** 记录一次失败，达到阈值则进入锁定；返回锁定到期时刻（未锁定为 null）。 */
    public Instant recordFailure(String username) {
        // 先应用可能已到期的旧锁定，避免在过期状态上累加
        if (isLocked(username)) {
            FailureState current = states.get(username);
            log.warn("失败发生在锁定窗口内: username={}, lockedUntil={}",
                    username, current == null ? null : current.lockedUntil());
            return current == null ? null : current.lockedUntil();
        }
        java.util.concurrent.atomic.AtomicReference<Instant> lockedUntilRef =
                new java.util.concurrent.atomic.AtomicReference<>();
        states.merge(username, new FailureState(1, null), (old, ignored) -> {
            int next = old.count() + 1;
            Instant lockedUntil = null;
            if (next >= properties.getMaxFailures()) {
                lockedUntil = timeProvider.now().plusSeconds(properties.getLockSeconds());
            }
            lockedUntilRef.set(lockedUntil);
            return new FailureState(next, lockedUntil);
        });
        Instant lockedUntil = lockedUntilRef.get();
        FailureState after = states.get(username);
        if (lockedUntil != null) {
            log.warn("连续失败达到阈值，账户临时锁定: username={}, failures={}, maxFailures={}, lockedUntil={}",
                    username, after.count(), properties.getMaxFailures(), lockedUntil);
        } else {
            log.warn("记录登录失败: username={}, failures={}, maxFailures={}",
                    username, after.count(), properties.getMaxFailures());
        }
        return lockedUntil;
    }

    /** 登录成功后重置计数。 */
    public void reset(String username) {
        states.remove(username);
        log.info("重置失败计数: username={}", username);
    }
}
