package com.github.h3yow.springbootidentitygatewayjava.auth.otp;

import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 按用户名保存当前有效的 OTP 挑战；新挑战覆盖旧挑战。
 * 所有方法以实例锁串行化，保证“读取-判定-标记消费”的原子性。
 */
@Component
public class OtpStore {

    private final java.util.Map<String, OtpChallenge> challenges = new java.util.HashMap<>();

    /** 保存/覆盖指定用户的挑战。 */
    public synchronized void save(OtpChallenge challenge) {
        challenges.put(challenge.username(), challenge);
    }

    /** 原子地读取并标记当前挑战为已消费；无挑战返回 empty。 */
    public synchronized Optional<OtpChallenge> consume(String username) {
        OtpChallenge current = challenges.get(username);
        if (current == null) {
            return Optional.empty();
        }
        challenges.put(username, current.asConsumed());
        return Optional.of(current);
    }

    /** 仅读取，不改变状态（供测试/诊断）。 */
    public synchronized Optional<OtpChallenge> peek(String username) {
        return Optional.ofNullable(challenges.get(username));
    }

    /** 清空全部挑战（测试隔离用）。 */
    public synchronized void clear() {
        challenges.clear();
    }
}
