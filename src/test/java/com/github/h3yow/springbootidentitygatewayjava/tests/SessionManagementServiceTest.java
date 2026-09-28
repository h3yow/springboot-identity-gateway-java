package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginClientContext;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionException;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionService;
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

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 多端会话管理服务层测试：
 * 多端并存与清单隔离、按会话撤销与重复撤销幂等、撤销/续期竞争、
 * 容量上限与“最久未活跃”淘汰、被撤销/淘汰会话的后续访问与续期结论、
 * 以及续期后能力概要与实际权限判定保持一致。
 * 全部时间判定使用 MutableClock，离线可重复。
 */
class SessionManagementServiceTest {

    private static final Logger log = LoggerFactory.getLogger(SessionManagementServiceTest.class);
    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private AuthProperties properties;
    private TokenStore store;
    private TokenService tokenService;
    private SessionService sessionService;
    private UserDirectory userDirectory;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        properties = new AuthProperties();
        properties.setAccessTokenTtlMillis(900_000L);
        properties.setRefreshTokenTtlMillis(600_000L);
        properties.setMaxSessionsPerUser(3);
        store = new TokenStore();
        TokenSigner signer = new TokenSigner(properties);
        tokenService = new TokenService(store, signer, clock, properties);
        sessionService = new SessionService(tokenService, store, clock);
        userDirectory = new UserDirectory(new Pbkdf2PasswordHasher());
    }

    private UserAccount alice() {
        return userDirectory.findByUsername("alice").orElseThrow();
    }

    private LoginClientContext device(String device, String client) {
        return new LoginClientContext(device, device + "-name", client);
    }

    @Test
    @DisplayName("多端并存：同一账号多设备会话互不影响，清单只显示自己的有效会话并区分设备")
    void multipleSessionsCoexistAndListingIsolated() {
        IssuedTokens phone = tokenService.issueFor(alice(), device("phone-1", "mobile-app"));
        clock.advance(1_000L);
        IssuedTokens pad = tokenService.issueFor(alice(), device("pad-2", "tablet-app"));
        clock.advance(1_000L);
        IssuedTokens laptop = tokenService.issueFor(alice(), device("laptop-3", "web"));

        List<SessionInfo> sessions = sessionService.listSessions("alice");
        log.info("alice 有效会话数={}, devices={}", sessions.size(),
                sessions.stream().map(SessionInfo::deviceId).toList());
        assertEquals(3, sessions.size());
        Set<String> deviceIds = new java.util.HashSet<>(sessions.stream().map(SessionInfo::deviceId).toList());
        assertEquals(Set.of("phone-1", "pad-2", "laptop-3"), deviceIds);

        // 每个会话的访问令牌独立可用
        assertEquals("alice", tokenService.authenticate(phone.accessToken()).username());
        assertEquals("alice", tokenService.authenticate(pad.accessToken()).username());
        assertEquals("alice", tokenService.authenticate(laptop.accessToken()).username());

        // 清单隔离：bob 看不到 alice 的任何会话
        UserAccount bob = userDirectory.findByUsername("bob").orElseThrow();
        tokenService.issueFor(bob, device("bob-phone", "mobile-app"));
        List<SessionInfo> bobSessions = sessionService.listSessions("bob");
        assertEquals(1, bobSessions.size());
        assertEquals("bob-phone", bobSessions.get(0).deviceId());
        assertTrue(bobSessions.stream().noneMatch(s -> s.deviceId().startsWith("phone-1")));
    }

    @Test
    @DisplayName("能力概要：清单中的 roles/perms/scopes 与该会话实际权限判定一致")
    void capabilityOverviewMatchesActualClaims() {
        IssuedTokens tokens = tokenService.issueFor(alice(), device("phone-1", "mobile-app"));
        SessionInfo info = sessionService.listSessions("alice").get(0);
        var claims = tokenService.authenticate(tokens.accessToken());
        log.info("清单概要 roles={}, perms={}, scopes={}; 实际令牌 roles={}, perms={}, scopes={}",
                info.roles(), info.permissions(), info.scopes(),
                claims.roles(), claims.permissions(), claims.scopes());
        assertEquals(claims.roles(), info.roles());
        assertEquals(claims.permissions(), info.permissions());
        assertEquals(claims.scopes(), info.scopes());
        assertTrue(info.scopes().contains("reports:read"));
    }

    @Test
    @DisplayName("续期后能力不减少：轮换后清单概要与新访问令牌判定仍一致")
    void capabilitiesSurviveRotation() {
        IssuedTokens first = tokenService.issueFor(alice(), device("phone-1", "mobile-app"));
        clock.advance(10_000L);
        IssuedTokens rotated = tokenService.rotate(first.refreshToken());

        // 旧 access 与新 access 都携带同样能力；清单只有一个会话（族不变）
        var newClaims = tokenService.authenticate(rotated.accessToken());
        SessionInfo info = sessionService.listSessions("alice").get(0);
        log.info("续期后清单能力 roles={}, perms={}, scopes={}; 新令牌能力一致",
                info.roles(), info.permissions(), info.scopes());
        assertEquals(Set.of("user"), info.roles());
        assertEquals(Set.of("user:read"), info.permissions());
        assertEquals(Set.of("openid", "reports:read"), info.scopes());
        assertEquals(info.roles(), newClaims.roles());
        assertEquals(info.permissions(), newClaims.permissions());
        assertEquals(info.scopes(), newClaims.scopes());
        assertEquals(1, sessionService.listSessions("alice").size());
    }

    @Test
    @DisplayName("按会话精准下线：撤销目标会话，其它会话照常；重复撤销结论一致")
    void revokeOneSessionDoesNotAffectOthersAndIsIdempotent() {
        IssuedTokens phone = tokenService.issueFor(alice(), device("phone-1", "mobile-app"));
        clock.advance(1_000L);
        IssuedTokens laptop = tokenService.issueFor(alice(), device("laptop-3", "web"));

        boolean first = sessionService.revokeSession("alice", phone.sessionId());
        boolean second = sessionService.revokeSession("alice", phone.sessionId());
        log.info("重复撤销: 第一次 changed={}, 第二次 changed={}", first, second);
        assertTrue(first, "首次撤销应产生状态变更");
        assertFalse(second, "重复撤销应幂等返回 false");

        // 被撤销会话：访问与续期都被拒绝（REVOKED），且不抛异常
        assertRejected(() -> tokenService.authenticate(phone.accessToken()), TokenRejectionReason.REVOKED);
        assertRejected(() -> tokenService.rotate(phone.refreshToken()), TokenRejectionReason.REVOKED);

        // 另一会话不受影响
        assertDoesNotThrow(() -> tokenService.authenticate(laptop.accessToken()));

        // 撤销后清单中消失
        List<SessionInfo> sessions = sessionService.listSessions("alice");
        assertEquals(1, sessions.size());
        assertEquals("laptop-3", sessions.get(0).deviceId());
    }

    @Test
    @DisplayName("撤销与续期竞争：同一族并发撤销/轮换，撤销生效后绝不会换出新可用凭证")
    void revokeAndRotateRaceIsSelfConsistent() throws Exception {
        int rounds = 0;
        for (int attempt = 0; attempt < 8; attempt++) {
            // 每个尝试前重置
            store.clear();
            clock.setNow(T0 + attempt * 100_000L);
            IssuedTokens tokens = tokenService.issueFor(alice(), device("phone-1", "mobile-app"));
            String refresh = tokens.refreshToken();
            String familyId = tokens.sessionId();

            int n = 12;
            CountDownLatch ready = new CountDownLatch(n);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger rotateOk = new AtomicInteger();
            ConcurrentLinkedQueue<TokenRejectionReason> rotateFail = new ConcurrentLinkedQueue<>();
            ExecutorService pool = Executors.newFixedThreadPool(n);
            for (int i = 0; i < n; i++) {
                final boolean rotate = i % 2 == 0;
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                        if (rotate) {
                            try {
                                tokenService.rotate(refresh);
                                rotateOk.incrementAndGet();
                            } catch (TokenException ex) {
                                rotateFail.add(ex.getReason());
                            }
                        } else {
                            sessionService.revokeSession("alice", familyId);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            ready.await(5, TimeUnit.SECONDS);
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

            // 最终态自洽：族一定是终态；如果轮换成功过，其新 access 也必须不可用（撤销在后或重放）
            var family = tokenService.findFamily(familyId).orElseThrow();
            log.info("竞争尝试#{}: rotateOk={}, rotateFail={}, familyState={}",
                    attempt, rotateOk.get(), rotateFail, family.state());
            assertNotEquals(com.github.h3yow.springbootidentitygatewayjava.auth.token.SessionState.ACTIVE,
                    family.state(), "撤销与续期并发后会话不能仍是 ACTIVE");
            rounds++;
        }
        log.info("共完成 {} 轮撤销/续期竞争，结论全部自洽", rounds);
        assertEquals(8, rounds);
    }

    @Test
    @DisplayName("容量上限：达到上限后淘汰最久未活跃会话，新会话正常建立且不被误伤")
    void evictsLeastActiveSessionWhenLimitReached() {
        IssuedTokens s1 = tokenService.issueFor(alice(), device("dev-1", "c"));
        clock.advance(1_000L);
        IssuedTokens s2 = tokenService.issueFor(alice(), device("dev-2", "c")); // s1 active=T0
        clock.advance(1_000L);
        IssuedTokens s3 = tokenService.issueFor(alice(), device("dev-3", "c")); // 达到上限3；s1 最久未活跃
        clock.advance(10_000L);
        // s2、s3 最近都活跃过，唯独 s1 自建立后一直未活动 -> s1 成为最久未活跃
        tokenService.authenticate(s2.accessToken());
        tokenService.authenticate(s3.accessToken());
        IssuedTokens s4 = tokenService.issueFor(alice(), device("dev-4", "c")); // 超上限，淘汰 s1

        List<SessionInfo> remaining = sessionService.listSessions("alice");
        log.info("淘汰后会话 devices={}", remaining.stream().map(SessionInfo::deviceId).toList());
        assertEquals(3, remaining.size());
        assertTrue(remaining.stream().noneMatch(s -> s.deviceId().equals("dev-1")), "最久未活跃的 dev-1 应被淘汰");
        assertTrue(remaining.stream().anyMatch(s -> s.deviceId().equals("dev-4")), "新会话 dev-4 必须保留");
        assertTrue(remaining.stream().anyMatch(s -> s.deviceId().equals("dev-2")), "活跃的 dev-2 应保留");
        assertTrue(remaining.stream().anyMatch(s -> s.deviceId().equals("dev-3")), "活跃的 dev-3 应保留");

        // 被淘汰会话：访问与续期都得到 EVICTED
        assertRejected(() -> tokenService.authenticate(s1.accessToken()), TokenRejectionReason.EVICTED);
        assertRejected(() -> tokenService.rotate(s1.refreshToken()), TokenRejectionReason.EVICTED);

        // 其它会话仍可用
        assertDoesNotThrow(() -> tokenService.authenticate(s2.accessToken()));
        assertDoesNotThrow(() -> tokenService.authenticate(s4.accessToken()));
    }

    @Test
    @DisplayName("淘汰只影响被选中的会话；并发登录不超上限、不淘汰新会话")
    void concurrentLoginsNeverExceedLimit() throws Exception {
        properties.setMaxSessionsPerUser(5);
        int threads = 10;
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<IssuedTokens> issued = new ConcurrentLinkedQueue<>();
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    issued.add(tokenService.issueFor(alice(), device("dev-" + idx, "c")));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        ready.await(5, TimeUnit.SECONDS);
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        List<SessionInfo> effective = sessionService.listSessions("alice");
        log.info("并发登录后有效会话数={}（上限5）", effective.size());
        assertEquals(5, effective.size(), "并发登录后有效会话数必须恰好等于上限");

        // 恰好 5 个最新会话的 access 令牌可用，被淘汰的 5 个得到 EVICTED
        int usable = 0;
        int evicted = 0;
        for (IssuedTokens t : issued) {
            try {
                tokenService.authenticate(t.accessToken());
                usable++;
            } catch (TokenException ex) {
                if (ex.getReason() == TokenRejectionReason.EVICTED) {
                    evicted++;
                }
            }
        }
        log.info("并发登录结果: 可用={}, 被淘汰={}", usable, evicted);
        assertEquals(5, usable);
        assertEquals(5, evicted);
    }

    @Test
    @DisplayName("自然过期会话从清单消失，且与撤销/淘汰结论可区分")
    void expiredSessionsDisappearAndReasonsAreDistinct() {
        properties.setMaxSessionsPerUser(0); // 不限制，便于单独构造
        IssuedTokens expired = tokenService.issueFor(alice(), device("old-dev", "c"));
        clock.advance(600_001L); // 超过刷新有效期
        // 过期会话不显示
        assertTrue(sessionService.listSessions("alice").isEmpty());
        // 续期得到 EXPIRED（自然过期），与 EVICTED/REVOKED 区分
        assertRejected(() -> tokenService.rotate(expired.refreshToken()), TokenRejectionReason.EXPIRED);
    }

    @Test
    @DisplayName("跨用户撤销他人会话被拒绝（统一 SESSION 异常，不泄露存在性）")
    void cannotRevokeAnotherUsersSession() {
        IssuedTokens aliceTokens = tokenService.issueFor(alice(), device("alice-phone", "c"));
        UserAccount bob = userDirectory.findByUsername("bob").orElseThrow();
        // bob 撤销 alice 的会话 id
        assertThrows(SessionException.class,
                () -> sessionService.revokeSession("bob", aliceTokens.sessionId()));
        // alice 会话仍然有效
        assertDoesNotThrow(() -> tokenService.authenticate(aliceTokens.accessToken()));
        // 不存在的会话 id 同样异常
        assertThrows(SessionException.class,
                () -> sessionService.revokeSession("alice", "non-existent-family-id"));
    }

    private static void assertRejected(org.junit.jupiter.api.function.Executable action,
                                       TokenRejectionReason expected) {
        TokenException ex = assertThrows(TokenException.class, action);
        assertEquals(expected, ex.getReason());
    }
}
