package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.LoginFailureTracker;
import com.github.h3yow.springbootidentitygatewayjava.auth.LoginService;
import com.github.h3yow.springbootidentitygatewayjava.auth.PendingLogin;
import com.github.h3yow.springbootidentitygatewayjava.auth.PendingLoginStore;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.error.ApiException;
import com.github.h3yow.springbootidentitygatewayjava.error.ErrorCode;
import com.github.h3yow.springbootidentitygatewayjava.support.MutableTimeProvider;
import com.github.h3yow.springbootidentitygatewayjava.token.AccessTokenStore;
import com.github.h3yow.springbootidentitygatewayjava.token.SessionStore;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenPair;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.user.Pbkdf2PasswordEncoder;
import com.github.h3yow.springbootidentitygatewayjava.user.UserStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 两步登录端到端（纯单元装配，无 Spring/网络/真实凭据）。
 * 使用固定时钟手动推进，覆盖：错误凭据、OTP 错误/过期/重复、连续失败锁定与到期恢复。
 */
class LoginServiceTest {

    private static final Logger log = LoggerFactory.getLogger(LoginServiceTest.class);
    private static final Instant T0 = Instant.parse("2026-09-23T00:00:00Z");

    private MutableTimeProvider clock;
    private AuthProperties props;
    private LoginService loginService;
    private LoginFailureTracker failureTracker;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeProvider(T0);
        props = new AuthProperties();
        props.setMaxFailures(3);
        props.setLockSeconds(300);
        props.setOtpTtlSeconds(300);
        props.setAccessTokenTtlSeconds(900);
        props.setRefreshTokenTtlSeconds(1200);
        props.setSessionMaxTtlSeconds(86400);

        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();
        UserStore userStore = new UserStore(props, encoder);
        userStore.register("alice", "alice-pw", Set.of("user"), Set.of("orders:read"));

        PendingLoginStore pendingStore = new PendingLoginStore(props, clock);
        failureTracker = new LoginFailureTracker(props, clock);
        SessionStore sessionStore = new SessionStore();
        AccessTokenStore accessTokenStore = new AccessTokenStore();
        TokenService tokenService = new TokenService(props, clock, sessionStore, accessTokenStore);
        loginService = new LoginService(userStore, pendingStore, failureTracker,
                tokenService, encoder, clock);
    }

    private ErrorCode expectFailure(String username, String password, String pendingToken, String otp) {
        try {
            if (password != null) {
                loginService.startPasswordLogin(username, password);
            } else {
                loginService.verifyOtpAndIssue(pendingToken, otp);
            }
            return null;
        } catch (ApiException e) {
            log.info("[输入] user={}, step={}, otp={}, now={} [判定] -> {}",
                    username, password != null ? "password" : "otp", otp, clock.now(), e.errorCode());
            return e.errorCode();
        }
    }

    private PendingLogin start() {
        return loginService.startPasswordLogin("alice", "alice-pw");
    }

    @Test
    void wrongPasswordIsDistinctFromLock() {
        ErrorCode c1 = expectFailure("alice", "wrong", null, null);
        ErrorCode c2 = expectFailure("alice", "wrong", null, null);
        assertEquals(ErrorCode.LOGIN_BAD_CREDENTIALS, c1);
        assertEquals(ErrorCode.LOGIN_BAD_CREDENTIALS, c2);
        log.info("[输入] 第 3 次错误密码 [判定依据] 达到 maxFailures=3 -> 应转为 LOCKED");
        ErrorCode c3 = expectFailure("alice", "wrong", null, null);
        assertEquals(ErrorCode.LOGIN_ACCOUNT_LOCKED, c3, "达到阈值应锁定");
        // 即使密码正确，锁定期内也拒绝，且原因仍是锁定
        ErrorCode c4 = expectFailure("alice", "alice-pw", null, null);
        assertEquals(ErrorCode.LOGIN_ACCOUNT_LOCKED, c4, "锁定期内正确密码也应拒绝");
    }

    @Test
    void lockExpiresAndLoginSucceedsAgain() {
        expectFailure("alice", "wrong", null, null);
        expectFailure("alice", "wrong", null, null);
        expectFailure("alice", "wrong", null, null);
        assertTrue(failureTracker.isLocked("alice"));
        clock.advanceSeconds(300);
        PendingLogin pending = start();
        TokenPair pair = loginService.verifyOtpAndIssue(pending.pendingToken(), pending.otpCode());
        log.info("[输入] 锁定窗口到期后正确凭据登录, now={} [判定] 签发 sessionId={}",
                clock.now(), pair.sessionId());
        assertEquals(pending.username(), "alice");
    }

    @Test
    void wrongOtpThenExpiredOtpAreDistinct() {
        PendingLogin pending = start();
        ErrorCode wrong = expectFailure("alice", null, pending.pendingToken(), "000000");
        assertEquals(ErrorCode.OTP_INVALID, wrong, "验证码错误应为 OTP_INVALID");

        // 上一次错误已消费该 OTP，同一 pendingToken 再次提交 -> 重复
        ErrorCode replay = expectFailure("alice", null, pending.pendingToken(), pending.otpCode());
        assertEquals(ErrorCode.OTP_REPLAYED, replay, "已消费 OTP 再用应为 OTP_REPLAYED");

        // 新的一次登录，推进时钟超过 OTP TTL -> 过期
        PendingLogin pending2 = start();
        clock.advanceSeconds(301);
        ErrorCode expired = expectFailure("alice", null, pending2.pendingToken(), pending2.otpCode());
        assertEquals(ErrorCode.OTP_EXPIRED, expired, "超过 TTL 应为 OTP_EXPIRED");
    }

    @Test
    void unknownPendingTokenIsRejected() {
        ErrorCode code = expectFailure("alice", null, "non-existent-token", "123456");
        assertEquals(ErrorCode.PENDING_LOGIN_NOT_FOUND, code);
    }

    @Test
    void concurrentOtpSubmissionExactlyOneSucceeds() throws Exception {
        PendingLogin pending = start();
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger replay = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    loginService.verifyOtpAndIssue(pending.pendingToken(), pending.otpCode());
                    success.incrementAndGet();
                } catch (ApiException e) {
                    if (e.errorCode() == ErrorCode.OTP_REPLAYED) {
                        replay.incrementAndGet();
                    } else {
                        other.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("[输入] {} 个并发相同 OTP 提交 [判定依据] CAS 一次性 -> success={}, replay={}, other={}",
                threads, success.get(), replay.get(), other.get());
        assertEquals(1, success.get(), "恰好一次成功");
        assertEquals(threads - 1, replay.get(), "其余全部为 OTP_REPLAYED");
        assertEquals(0, other.get());
    }
}
