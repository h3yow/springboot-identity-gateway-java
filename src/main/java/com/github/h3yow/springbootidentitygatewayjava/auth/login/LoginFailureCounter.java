package com.github.h3yow.springbootidentitygatewayjava.auth.login;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 按用户名统计连续失败次数并执行临时锁定；锁定窗口到期自动恢复。
 * 判定规则：
 * <ul>
 *   <li>失败次数达到 auth.max-failures 时，锁定至 now + auth.lock-millis</li>
 *   <li>窗口到期后，下一次访问自动清零并恢复可登录</li>
 *   <li>登录成功立即清零</li>
 * </ul>
 */
@Component
public class LoginFailureCounter {

    private static final Logger log = LoggerFactory.getLogger(LoginFailureCounter.class);

    private record State(int failures, long lockedUntilMillis) {
    }

    private final Map<String, State> states = new HashMap<>();
    private final Clock clock;
    private final AuthProperties properties;

    public LoginFailureCounter(Clock clock, AuthProperties properties) {
        this.clock = clock;
        this.properties = properties;
    }

    /** 当前是否处于锁定状态（窗口到期自动解除）。 */
    public synchronized boolean isLocked(String username) {
        State state = effectiveState(username);
        boolean locked = state.lockedUntilMillis() > clock.nowMillis();
        if (locked) {
            log.info("锁定判定: username={}, failures={}, now={}, lockedUntil={}, 依据=当前时间在锁定窗口内",
                    username, state.failures(), clock.nowMillis(), state.lockedUntilMillis());
        }
        return locked;
    }

    /** 记录一次失败，达到阈值则锁定；返回当前是否已锁定。 */
    public synchronized boolean recordFailure(String username) {
        State state = effectiveState(username);
        int failures = state.failures() + 1;
        long now = clock.nowMillis();
        long lockedUntil = state.lockedUntilMillis();
        if (failures >= properties.getMaxFailures()) {
            lockedUntil = now + properties.getLockMillis();
            log.warn("触发锁定: username={}, failures={}, 阈值={}, lockedUntil={}, lockMs={}",
                    username, failures, properties.getMaxFailures(), lockedUntil, properties.getLockMillis());
        } else {
            log.info("记录登录失败: username={}, failures={}, 阈值={}", username, failures, properties.getMaxFailures());
        }
        states.put(username, new State(failures, lockedUntil));
        return lockedUntil > now;
    }

    /** 登录成功后清零失败记录。 */
    public synchronized void reset(String username) {
        states.remove(username);
        log.info("失败计数清零: username={}", username);
    }

    /** 当前连续失败次数（测试/诊断用）。 */
    public synchronized int currentFailures(String username) {
        return effectiveState(username).failures();
    }

    /** 当前锁定截止时间（毫秒），未锁定返回 0。 */
    public synchronized long lockedUntil(String username) {
        State state = effectiveState(username);
        return state.lockedUntilMillis() > clock.nowMillis() ? state.lockedUntilMillis() : 0L;
    }

    /** 清空全部失败/锁定状态（测试隔离用）。 */
    public synchronized void clear() {
        states.clear();
    }

    /**
     * 返回当前有效状态：若锁定窗口已过期，视为自动恢复（清零并持久化）。
     */
    private State effectiveState(String username) {
        State state = states.get(username);
        if (state == null) {
            return new State(0, 0L);
        }
        if (state.lockedUntilMillis() > 0 && clock.nowMillis() >= state.lockedUntilMillis()) {
            log.info("锁定窗口到期自动恢复: username={}, now={}, lockedUntil={}",
                    username, clock.nowMillis(), state.lockedUntilMillis());
            State cleared = new State(0, 0L);
            states.put(username, cleared);
            return cleared;
        }
        return state;
    }
}
