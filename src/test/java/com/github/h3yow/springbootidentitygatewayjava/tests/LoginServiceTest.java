package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginException;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginFailureCounter;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginFailureReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginService;
import com.github.h3yow.springbootidentitygatewayjava.auth.otp.OtpService;
import com.github.h3yow.springbootidentitygatewayjava.auth.otp.OtpStore;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 两步登录测试：凭据错误、OTP 过期/重放/错误、连续失败锁定与窗口到期自动恢复。
 * 时间全部由 {@link MutableClock} 控制，不依赖系统时钟与外部服务。
 */
class LoginServiceTest {

    private static final Logger log = LoggerFactory.getLogger(LoginServiceTest.class);

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private AuthProperties properties;
    private LoginService loginService;
    private LoginFailureCounter failureCounter;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        properties = new AuthProperties();
        properties.setMaxFailures(3);
        properties.setLockMillis(60_000L);
        properties.setOtpTtlMillis(30_000L);

        Pbkdf2PasswordHasher hasher = new Pbkdf2PasswordHasher();
        UserDirectory users = new UserDirectory(hasher);
        OtpStore otpStore = new OtpStore();
        OtpService otpService = new OtpService(otpStore, clock, properties);
        failureCounter = new LoginFailureCounter(clock, properties);
        loginService = new LoginService(users, hasher, otpService, failureCounter);
    }

    @Test
    @DisplayName("正确密码+正确OTP可完成两步登录")
    void happyPath() {
        log.info("输入: username=alice, password=password-alice");
        String otp = loginService.verifyPassword("alice", "password-alice");
        log.info("第一步结论: OTP 已签发, otp=<{}>", otp);
        String username = loginService.verifyOtp("alice", otp);
        log.info("第二步结论: 登录成功 username={}", username);
        assertEquals("alice", username);
        assertEquals(0, failureCounter.currentFailures("alice"));
    }

    @Test
    @DisplayName("密码错误返回 BAD_CREDENTIALS 并累计失败次数")
    void badPassword() {
        log.info("输入: username=alice, password=wrong-password");
        LoginException ex = assertThrows(LoginException.class,
                () -> loginService.verifyPassword("alice", "wrong-password"));
        log.info("判定依据: 用户存在但 PBKDF2 比对不一致 -> reason={}", ex.getReason());
        assertEquals(LoginFailureReason.BAD_CREDENTIALS, ex.getReason());
        assertEquals(1, failureCounter.currentFailures("alice"));
    }

    @Test
    @DisplayName("用户不存在与密码错误均返回 BAD_CREDENTIALS（不泄露用户是否存在）")
    void unknownUser() {
        log.info("输入: username=ghost, password=whatever");
        LoginException ex = assertThrows(LoginException.class,
                () -> loginService.verifyPassword("ghost", "whatever"));
        log.info("判定依据: 用户目录中不存在该用户 -> reason={}", ex.getReason());
        assertEquals(LoginFailureReason.BAD_CREDENTIALS, ex.getReason());
    }

    @Test
    @DisplayName("连续失败达到阈值后临时锁定，返回 ACCOUNT_LOCKED")
    void lockedAfterMaxFailures() {
        for (int i = 1; i <= 3; i++) {
            log.info("输入: 第{}次错误密码 username=bob", i);
            LoginException ex = assertThrows(LoginException.class,
                    () -> loginService.verifyPassword("bob", "bad"));
            log.info("第{}次失败结论: reason={}, failures={}", i, ex.getReason(),
                    failureCounter.currentFailures("bob"));
            if (i < 3) {
                assertEquals(LoginFailureReason.BAD_CREDENTIALS, ex.getReason());
            } else {
                assertEquals(LoginFailureReason.ACCOUNT_LOCKED, ex.getReason());
            }
        }
        // 锁定期间即使密码正确也拒绝
        log.info("输入: 锁定期间使用正确密码 username=bob");
        LoginException locked = assertThrows(LoginException.class,
                () -> loginService.verifyPassword("bob", "password-bob"));
        log.info("判定依据: now={} < lockedUntil={} -> reason={}", clock.nowMillis(),
                failureCounter.lockedUntil("bob"), locked.getReason());
        assertEquals(LoginFailureReason.ACCOUNT_LOCKED, locked.getReason());
        assertTrue(failureCounter.lockedUntil("bob") > clock.nowMillis());
    }

    @Test
    @DisplayName("锁定窗口到期后自动恢复为可登录状态")
    void lockExpiresAutomatically() {
        for (int i = 0; i < 3; i++) {
            assertThrows(LoginException.class, () -> loginService.verifyPassword("bob", "bad"));
        }
        long lockedUntil = failureCounter.lockedUntil("bob");
        log.info("已触发锁定: now={}, lockedUntil={}", clock.nowMillis(), lockedUntil);

        // 差 1ms 到期仍锁定
        clock.advance(59_999L);
        log.info("推进时间到窗口到期前1ms: now={}", clock.nowMillis());
        assertTrue(failureCounter.isLocked("bob"), "窗口内仍应锁定");

        // 到期时刻自动恢复，失败计数清零，可正常登录
        clock.advance(1L);
        log.info("推进时间到窗口到期: now={} >= lockedUntil={}", clock.nowMillis(), lockedUntil);
        assertFalse(failureCounter.isLocked("bob"), "窗口到期应自动解除锁定");
        assertEquals(0, failureCounter.currentFailures("bob"), "恢复后失败计数应清零");

        String otp = loginService.verifyPassword("bob", "password-bob");
        log.info("恢复后第一步结论: OTP 已签发");
        assertEquals("bob", loginService.verifyOtp("bob", otp));
        log.info("恢复后第二步结论: 登录成功");
    }

    @Test
    @DisplayName("OTP 过期返回 OTP_EXPIRED")
    void otpExpired() {
        String otp = loginService.verifyPassword("alice", "password-alice");
        log.info("OTP 已签发 ttl=30000ms, 推进时钟 30001ms 后提交 otp=<{}>", otp);
        clock.advance(30_001L);
        LoginException ex = assertThrows(LoginException.class,
                () -> loginService.verifyOtp("alice", otp));
        log.info("判定依据: now={} > expiresAt -> reason={}", clock.nowMillis(), ex.getReason());
        assertEquals(LoginFailureReason.OTP_EXPIRED, ex.getReason());
    }

    @Test
    @DisplayName("OTP 重复提交返回 OTP_REUSED（第二次拒绝）")
    void otpReplay() {
        String otp = loginService.verifyPassword("alice", "password-alice");
        log.info("首次提交 OTP otp=<{}>", otp);
        assertEquals("alice", loginService.verifyOtp("alice", otp));
        log.info("重复提交同一 OTP");
        LoginException ex = assertThrows(LoginException.class,
                () -> loginService.verifyOtp("alice", otp));
        log.info("判定依据: 挑战已被消费 -> reason={}", ex.getReason());
        assertEquals(LoginFailureReason.OTP_REUSED, ex.getReason());
    }

    @Test
    @DisplayName("OTP 错误返回 OTP_MISMATCH")
    void otpMismatch() {
        loginService.verifyPassword("alice", "password-alice");
        log.info("输入: username=alice, otp=000000（错误码）");
        LoginException ex = assertThrows(LoginException.class,
                () -> loginService.verifyOtp("alice", "000000"));
        log.info("判定依据: 哈希比对不一致 -> reason={}", ex.getReason());
        assertEquals(LoginFailureReason.OTP_MISMATCH, ex.getReason());
    }

    @Test
    @DisplayName("未完成第一步直接提交OTP返回 OTP_MISSING")
    void otpWithoutChallenge() {
        log.info("输入: username=alice, otp=123456（无挑战）");
        LoginException ex = assertThrows(LoginException.class,
                () -> loginService.verifyOtp("alice", "123456"));
        log.info("判定依据: OtpStore 无该用户挑战 -> reason={}", ex.getReason());
        assertEquals(LoginFailureReason.OTP_MISSING, ex.getReason());
    }
}
