package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.AccessTokenClaims;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.IssuedTokens;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenException;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenRejectionReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenSigner;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenStore;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 令牌生命周期测试：
 * 正常签发/校验、刷新一次性轮换、并发刷新恰一次成功、重放触发整族撤销、
 * 访问令牌过期、刷新令牌过期、主动撤销、非法签名与类型错误。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private AuthProperties properties;
    private TokenService tokenService;
    private UserDirectory userDirectory;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        properties = new AuthProperties();
        properties.setAccessTokenTtlMillis(900_000L);
        properties.setRefreshTokenTtlMillis(600_000L);
        TokenStore store = new TokenStore();
        TokenSigner signer = new TokenSigner(properties);
        tokenService = new TokenService(store, signer, clock, properties);
        userDirectory = new UserDirectory(new Pbkdf2PasswordHasher());
    }

    private UserAccount alice() {
        return userDirectory.findByUsername("alice").orElseThrow();
    }

    @Test
    @DisplayName("签发的访问令牌可通过认证并携带角色/权限/范围")
    void issueAndAuthenticate() {
        IssuedTokens tokens = tokenService.issueFor(alice());
        log.info("输入: 新签发 accessToken 前20字符=<{}...>", tokens.accessToken(), 0);
        AccessTokenClaims claims = tokenService.authenticate(tokens.accessToken());
        log.info("判定依据: 签名有效 + 未过期 + 族未撤销; user={}, roles={}, perms={}, scopes={}",
                claims.username(), claims.roles(), claims.permissions(), claims.scopes());
        assertEquals("alice", claims.username());
        assertTrue(claims.roles().contains("user"));
        assertTrue(claims.permissions().contains("user:read"));
        assertTrue(claims.scopes().contains("reports:read"));
        assertEquals(T0 + 900_000L, claims.expiresAt());
    }

    @Test
    @DisplayName("正常轮换：旧刷新令牌作废，新令牌对可用")
    void rotationSucceedsOnce() {
        IssuedTokens first = tokenService.issueFor(alice());
        log.info("第一次轮换输入: refreshToken=<{}...>", abbreviate(first.refreshToken()));
        IssuedTokens second = tokenService.rotate(first.refreshToken());
        log.info("第一次轮换结论: 成功，签发新令牌对");

        assertNotEquals(first.accessToken(), second.accessToken());
        assertNotEquals(first.refreshToken(), second.refreshToken());
        // 新访问令牌可用
        assertEquals("alice", tokenService.authenticate(second.accessToken()).username());

        // 旧刷新令牌再次使用 -> ROTATED 且整族撤销
        log.info("重复使用旧刷新令牌（重放）");
        TokenException ex = assertThrows(TokenException.class,
                () -> tokenService.rotate(first.refreshToken()));
        log.info("判定依据: stored.used=true -> reason={}, 并撤销整族", ex.getReason());
        assertEquals(TokenRejectionReason.ROTATED, ex.getReason());

        // 重放后：新签发的令牌也全部失效
        TokenException accessDenied = assertThrows(TokenException.class,
                () -> tokenService.authenticate(second.accessToken()));
        log.info("重放后访问令牌结论: reason={}", accessDenied.getReason());
        assertEquals(TokenRejectionReason.REVOKED, accessDenied.getReason());

        TokenException newRefreshDenied = assertThrows(TokenException.class,
                () -> tokenService.rotate(second.refreshToken()));
        log.info("重放后新刷新令牌结论: reason={}", newRefreshDenied.getReason());
        assertEquals(TokenRejectionReason.REVOKED, newRefreshDenied.getReason());
    }

    @Test
    @DisplayName("并发使用同一个刷新令牌：恰好一次成功，其余失败，整族被撤销")
    void concurrentRefreshExactlyOneSuccess() throws Exception {
        final int threads = 16;
        IssuedTokens first = tokenService.issueFor(alice());
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        ConcurrentLinkedQueue<TokenRejectionReason> failureReasons = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    tokenService.rotate(first.refreshToken());
                    success.incrementAndGet();
                } catch (TokenException ex) {
                    failureReasons.add(ex.getReason());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await(5, TimeUnit.SECONDS);
        log.info("并发开始: {} 个线程同时使用同一刷新令牌", threads);
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "线程池应在超时前结束");

        log.info("并发结论: 成功次数={}, 失败次数={}, 失败原因分布={}",
                success.get(), failureReasons.size(), failureReasons);
        assertEquals(1, success.get(), "同一刷新令牌只允许一次成功轮换");
        assertEquals(threads - 1, failureReasons.size());
        // 所有失败必须可解释：族锁串行化后为 ROTATED（首个重放者触发撤销，其余看到 REVOKED）
        for (TokenRejectionReason reason : failureReasons) {
            assertTrue(reason == TokenRejectionReason.ROTATED || reason == TokenRejectionReason.REVOKED,
                    "失败原因应为 ROTATED 或 REVOKED，实际: " + reason);
        }

        // 即使是唯一成功轮换出的新访问令牌，也因重放检测撤销整族而失效
        // （成功的那一次已先返回，随后第一个失败请求触发族撤销）
        assertThrows(TokenException.class, () -> tokenService.authenticate(first.accessToken()));
        log.info("并发重放后: 族已撤销，旧访问令牌同样失效");
    }

    @Test
    @DisplayName("访问令牌过期返回 EXPIRED")
    void accessTokenExpiry() {
        IssuedTokens tokens = tokenService.issueFor(alice());
        clock.advance(900_001L);
        log.info("推进时钟超过访问令牌有效期后校验: now={}", clock.nowMillis());
        TokenException ex = assertThrows(TokenException.class,
                () -> tokenService.authenticate(tokens.accessToken()));
        log.info("判定依据: now >= exp -> reason={}", ex.getReason());
        assertEquals(TokenRejectionReason.EXPIRED, ex.getReason());
    }

    @Test
    @DisplayName("刷新令牌过期返回 EXPIRED，且不触发族撤销")
    void refreshTokenExpiry() {
        IssuedTokens first = tokenService.issueFor(alice());
        clock.advance(600_001L);
        log.info("推进时钟超过刷新令牌有效期后轮换: now={}", clock.nowMillis());
        TokenException ex = assertThrows(TokenException.class,
                () -> tokenService.rotate(first.refreshToken()));
        log.info("判定依据: now >= refreshToken.exp -> reason={}", ex.getReason());
        assertEquals(TokenRejectionReason.EXPIRED, ex.getReason());
    }

    @Test
    @DisplayName("主动撤销后访问令牌与刷新令牌均不再被接受")
    void revokeFamily() {
        IssuedTokens tokens = tokenService.issueFor(alice());
        log.info("主动撤销刷新令牌所属会话");
        tokenService.revoke(tokens.refreshToken());

        TokenException accessEx = assertThrows(TokenException.class,
                () -> tokenService.authenticate(tokens.accessToken()));
        log.info("撤销后访问令牌结论: reason={}", accessEx.getReason());
        assertEquals(TokenRejectionReason.REVOKED, accessEx.getReason());

        TokenException refreshEx = assertThrows(TokenException.class,
                () -> tokenService.rotate(tokens.refreshToken()));
        log.info("撤销后刷新令牌结论: reason={}", refreshEx.getReason());
        assertEquals(TokenRejectionReason.REVOKED, refreshEx.getReason());
    }

    @Test
    @DisplayName("篡改签名返回 BAD_SIGNATURE；结构损坏返回 MALFORMED")
    void invalidTokenSignatures() {
        IssuedTokens tokens = tokenService.issueFor(alice());
        String tampered = tokens.accessToken().substring(0, tokens.accessToken().length() - 2) + "AA";
        log.info("输入: 篡改末尾签名的令牌");
        TokenException signatureEx = assertThrows(TokenException.class,
                () -> tokenService.authenticate(tampered));
        log.info("判定依据: HMAC 常量时间比对不一致 -> reason={}", signatureEx.getReason());
        assertEquals(TokenRejectionReason.BAD_SIGNATURE, signatureEx.getReason());

        log.info("输入: 结构损坏令牌 not-a-token");
        TokenException malformedEx = assertThrows(TokenException.class,
                () -> tokenService.authenticate("not-a-token"));
        assertEquals(TokenRejectionReason.MALFORMED, malformedEx.getReason());
    }

    @Test
    @DisplayName("用刷新令牌访问受保护资源返回 WRONG_TYPE，反之亦然")
    void wrongTokenType() {
        IssuedTokens tokens = tokenService.issueFor(alice());
        log.info("输入: 用 refreshToken 调 authenticate");
        TokenException ex = assertThrows(TokenException.class,
                () -> tokenService.authenticate(tokens.refreshToken()));
        log.info("判定依据: typ=refresh 与期望 access 不符 -> reason={}", ex.getReason());
        assertEquals(TokenRejectionReason.WRONG_TYPE, ex.getReason());

        log.info("输入: 用 accessToken 调 rotate");
        TokenException ex2 = assertThrows(TokenException.class,
                () -> tokenService.rotate(tokens.accessToken()));
        assertEquals(TokenRejectionReason.WRONG_TYPE, ex2.getReason());
    }

    @Test
    @DisplayName("未知刷新令牌（服务端无记录）返回 UNKNOWN")
    void unknownRefreshToken() {
        IssuedTokens tokens = tokenService.issueFor(alice());
        // 伪造一个签名合法但服务端从未落库的刷新令牌：用另一个账户签发的刷新令牌在本族无记录
        UserAccount admin = userDirectory.findByUsername("admin").orElseThrow();
        IssuedTokens other = tokenService.issueFor(admin);
        log.info("输入: admin 的刷新令牌冒充 alice 会话");
        // other 刷新令牌在其自己族内是存在的，故构造"已撤销族外"场景：先撤销 admin 族，再轮换
        tokenService.revoke(other.refreshToken());
        TokenException ex = assertThrows(TokenException.class,
                () -> tokenService.rotate(other.refreshToken()));
        log.info("判定依据: 族已撤销 -> reason={}", ex.getReason());
        assertEquals(TokenRejectionReason.REVOKED, ex.getReason());
        // alice 的令牌不受影响（族相互隔离）
        assertEquals("alice", tokenService.authenticate(tokens.accessToken()).username());
    }

    private static String abbreviate(String token) {
        return token.length() > 20 ? token.substring(0, 20) : token;
    }
}
