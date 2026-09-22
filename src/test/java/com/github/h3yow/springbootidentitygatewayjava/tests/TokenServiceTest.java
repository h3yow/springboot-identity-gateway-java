package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.error.ApiException;
import com.github.h3yow.springbootidentitygatewayjava.error.ErrorCode;
import com.github.h3yow.springbootidentitygatewayjava.support.MutableTimeProvider;
import com.github.h3yow.springbootidentitygatewayjava.token.AccessTokenStore;
import com.github.h3yow.springbootidentitygatewayjava.token.SessionStore;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenPair;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 令牌签发/轮换/重放/并发/过期/撤销。固定时钟手动推进，不依赖真实时间。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);
    private static final Instant T0 = Instant.parse("2026-09-23T00:00:00Z");

    private MutableTimeProvider clock;
    private AuthProperties props;
    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        clock = new MutableTimeProvider(T0);
        props = new AuthProperties();
        props.setAccessTokenTtlSeconds(900);
        props.setRefreshTokenTtlSeconds(1200);
        props.setSessionMaxTtlSeconds(86400);
        tokenService = new TokenService(props, clock, new SessionStore(), new AccessTokenStore());
    }

    private TokenPair issue() {
        return tokenService.issue("alice", Set.of("user"), Set.of("orders:read"));
    }

    private ErrorCode failureOf(Runnable r) {
        try {
            r.run();
            return null;
        } catch (ApiException e) {
            return e.errorCode();
        }
    }

    @Test
    void rotateIssuesNewPairAndInvalidatesOldRefreshToken() {
        TokenPair first = issue();
        TokenPair second = tokenService.refresh(first.refreshToken());
        log.info("[输入] 首次 refreshToken 轮换 [判定依据] 新旧 access/refresh 必须不同");
        assertNotEquals(first.accessToken(), second.accessToken());
        assertNotEquals(first.refreshToken(), second.refreshToken());

        ErrorCode replay = failureOf(() -> tokenService.refresh(first.refreshToken()));
        log.info("[输入] 再次使用旧 refreshToken [判定] -> {}（应吊销整族）", replay);
        assertEquals(ErrorCode.REFRESH_REPLAYED, replay);

        // 整族失效：第二次轮换得到的刷新令牌与第一次的访问令牌都不再被接受
        ErrorCode newer = failureOf(() -> tokenService.refresh(second.refreshToken()));
        ErrorCode oldAccess = failureOf(() -> tokenService.verifyAccessToken(first.accessToken()));
        ErrorCode newAccess = failureOf(() -> tokenService.verifyAccessToken(second.accessToken()));
        log.info("[输入] 重放后校验同族令牌 [判定] 新refresh={}, 旧access={}, 新access={}",
                newer, oldAccess, newAccess);
        assertEquals(ErrorCode.REFRESH_REPLAYED, newer);
        assertEquals(ErrorCode.TOKEN_REVOKED, oldAccess);
        assertEquals(ErrorCode.TOKEN_REVOKED, newAccess);
    }

    @Test
    void concurrentRefreshExactlyOneSucceedsAndFamilyRevoked() throws Exception {
        TokenPair first = issue();
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        AtomicInteger replay = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();
        List<String> winners = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    TokenPair p = tokenService.refresh(first.refreshToken());
                    success.incrementAndGet();
                    winners.add(p.refreshToken());
                } catch (ApiException e) {
                    if (e.errorCode() == ErrorCode.REFRESH_REPLAYED) {
                        replay.incrementAndGet();
                    } else {
                        other.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("[输入] {} 个并发使用同一 refreshToken [判定依据] 会话内加锁一次性 -> success={}, replay={}, other={}",
                threads, success.get(), replay.get(), other.get());
        assertEquals(1, success.get(), "并发刷新恰好一次成功");
        assertEquals(threads - 1, replay.get(), "其余全部 REFRESH_REPLAYED");
        assertEquals(0, other.get());

        // 唯一成功者拿到的新刷新令牌也应因整族吊销而无法使用
        String winnerRefresh = winners.get(0);
        ErrorCode after = failureOf(() -> tokenService.refresh(winnerRefresh));
        log.info("[输入] 唯一获胜者随后再刷新 [判定] -> {}（整族已吊销）", after);
        assertEquals(ErrorCode.REFRESH_REPLAYED, after);
    }

    @Test
    void expiredAccessTokenAndRefreshTokenAreRejectedDistinctly() {
        TokenPair pair = issue();

        clock.advanceSeconds(901); // 超过 access TTL
        ErrorCode accessExpired = failureOf(() -> tokenService.verifyAccessToken(pair.accessToken()));
        log.info("[输入] 推进 {}s 校验 accessToken [判定] -> {}", 901, accessExpired);
        assertEquals(ErrorCode.TOKEN_EXPIRED, accessExpired);

        clock.advanceSeconds(300); // 累计 1201s，超过 refresh TTL
        ErrorCode refreshExpired = failureOf(() -> tokenService.refresh(pair.refreshToken()));
        log.info("[输入] 累计 {}s 使用 refreshToken [判定] -> {}", 1201, refreshExpired);
        assertEquals(ErrorCode.TOKEN_EXPIRED, refreshExpired);
    }

    @Test
    void absoluteSessionExpiryRevokesFamily() {
        // 让会话绝对上限远短于访问令牌自身寿命，
        // 从而纯粹验证“会话绝对过期导致整族吊销”，而非访问令牌先自然过期。
        props.setAccessTokenTtlSeconds(100_000);
        props.setRefreshTokenTtlSeconds(100_000);
        props.setSessionMaxTtlSeconds(100);
        TokenPair pair = issue();
        clock.advanceSeconds(101); // 超过会话绝对上限，但访问令牌自身尚未过期

        // 访问令牌自身未过期，但会话已过绝对有效期 -> 按过期拒绝（区别于撤销）
        ErrorCode access = failureOf(() -> tokenService.verifyAccessToken(pair.accessToken()));
        log.info("[输入] 推进 101s（会话上限 100s，access 寿命 100000s）校验 accessToken [判定] -> {}", access);
        assertEquals(ErrorCode.TOKEN_EXPIRED, access);

        ErrorCode code = failureOf(() -> tokenService.refresh(pair.refreshToken()));
        log.info("[输入] 同条件下刷新 [判定] -> {}", code);
        assertEquals(ErrorCode.TOKEN_EXPIRED, code);
    }

    @Test
    void logoutRevokesAllTokensInSession() {
        TokenPair pair = issue();
        tokenService.revokeSession(pair.sessionId());
        ErrorCode access = failureOf(() -> tokenService.verifyAccessToken(pair.accessToken()));
        ErrorCode refresh = failureOf(() -> tokenService.refresh(pair.refreshToken()));
        log.info("[输入] 登出后 [判定] access={}, refresh={}", access, refresh);
        assertEquals(ErrorCode.TOKEN_REVOKED, access);
        // 登出摘除当前刷新索引，按“无效/重放”处理
        assertEquals(ErrorCode.REFRESH_REPLAYED, refresh);
    }

    @Test
    void missingMalformedAndUnknownTokensAreRejected() {
        ErrorCode missing = failureOf(() -> tokenService.verifyAccessToken(null));
        ErrorCode malformed = failureOf(() -> tokenService.verifyAccessToken("at_garbage"));
        log.info("[输入] null/未知令牌 [判定] missing={}, malformed={}", missing, malformed);
        assertEquals(ErrorCode.TOKEN_MISSING, missing);
        assertEquals(ErrorCode.TOKEN_MALFORMED, malformed);
    }
}
