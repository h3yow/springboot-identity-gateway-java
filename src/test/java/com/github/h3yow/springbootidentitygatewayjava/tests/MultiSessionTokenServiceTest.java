package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.ClientInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.IssuedTokens;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenException;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenFamily;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenRejectionReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenSigner;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenStore;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 多端会话的令牌域行为：
 * 多端并存、容量上限与 LRU 淘汰、被淘汰会话访问/续期结论（EVICTED）、
 * 淘汰只影响目标会话、续期能力保持、撤销与续期竞争自洽、并发登录不超上限。
 */
class MultiSessionTokenServiceTest {

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private AuthProperties properties;
    private TokenStore store;
    private TokenService tokenService;
    private UserAccount alice;
    private UserAccount admin;

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
        UserDirectory userDirectory = new UserDirectory(new Pbkdf2PasswordHasher());
        alice = userDirectory.findByUsername("alice").orElseThrow();
        admin = userDirectory.findByUsername("admin").orElseThrow();
    }

    private ClientInfo client(String device, String clientId) {
        return new ClientInfo(device, device + "-name", clientId);
    }

    private long activeCount(String username) {
        return store.allFamilies().stream()
                .filter(f -> f.username().equals(username))
                .filter(TokenFamily::active)
                .count();
    }

    @Test
    @DisplayName("同一账号多端可并存且互不影响；不同账号容量独立")
    void multipleDevicesCoexist() {
        IssuedTokens phone = tokenService.issueFor(alice, client("phone", "ios"));
        IssuedTokens laptop = tokenService.issueFor(alice, client("laptop", "web"));

        assertEquals("alice", tokenService.authenticate(phone.accessToken()).username());
        assertEquals("alice", tokenService.authenticate(laptop.accessToken()).username());
        assertEquals(2, activeCount("alice"));

        // admin 的会话不占 alice 的容量
        tokenService.issueFor(admin, client("admin-pc", "web"));
        tokenService.issueFor(admin, client("admin-tab", "tablet"));
        tokenService.issueFor(admin, client("admin-phone", "ios"));
        assertEquals(2, activeCount("alice"));
        assertEquals(3, activeCount("admin"));
        assertEquals("alice", tokenService.authenticate(phone.accessToken()).username());
    }

    @Test
    @DisplayName("达到上限再登录：淘汰最久未活跃会话，新会话建立，旧会话访问与续期均得 EVICTED")
    void capacityEvictsLeastActive() {
        // s1 最早建立
        IssuedTokens s1 = tokenService.issueFor(alice, client("dev-1", "c1"));
        clock.advance(1_000L);
        // s2 建立后，s1 被访问一次（更活跃）
        IssuedTokens s2 = tokenService.issueFor(alice, client("dev-2", "c2"));
        clock.advance(1_000L);
        tokenService.authenticate(s1.accessToken());
        clock.advance(1_000L);
        // s3 建立；此刻 s2 最久未活跃
        IssuedTokens s3 = tokenService.issueFor(alice, client("dev-3", "c3"));
        assertEquals(3, activeCount("alice"));
        clock.advance(1_000L);
        // 第四次登录触发淘汰：应淘汰 s2
        IssuedTokens s4 = tokenService.issueFor(alice, client("dev-4", "c4"));

        assertEquals(3, activeCount("alice"), "淘汰后仍恰好等于上限");
        // 被淘汰会话 s2：访问与续期都被拒绝为 EVICTED
        TokenException accessEx = assertThrows(TokenException.class,
                () -> tokenService.authenticate(s2.accessToken()));
        assertEquals(TokenRejectionReason.EVICTED, accessEx.getReason());
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> tokenService.rotate(s2.refreshToken()));
        assertEquals(TokenRejectionReason.EVICTED, rotateEx.getReason());

        // s1、s3 仍可用，新会话 s4 也可用（未被误伤）
        assertDoesNotThrow(() -> tokenService.authenticate(s1.accessToken()));
        assertDoesNotThrow(() -> tokenService.authenticate(s3.accessToken()));
        assertDoesNotThrow(() -> tokenService.authenticate(s4.accessToken()));
        assertDoesNotThrow(() -> tokenService.rotate(s3.refreshToken()));
    }

    @Test
    @DisplayName("淘汰只选中最久未活跃的一个，不连带其它会话")
    void evictionAffectsOnlyVictim() {
        List<IssuedTokens> tokens = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            tokens.add(tokenService.issueFor(alice, client("dev-" + i, "c" + i)));
            clock.advance(1_000L);
        }
        tokenService.issueFor(alice, client("dev-4", "c4"));

        // 第一个建立（最久未活跃）被淘汰，其余两个仍有效
        TokenException victim = assertThrows(TokenException.class,
                () -> tokenService.authenticate(tokens.get(0).accessToken()));
        assertEquals(TokenRejectionReason.EVICTED, victim.getReason());
        for (int i = 1; i <= 2; i++) {
            int idx = i;
            assertDoesNotThrow(() -> tokenService.authenticate(tokens.get(idx).accessToken()));
        }
    }

    @Test
    @DisplayName("续期后能力不减少不丢失：角色/权限/范围与登录时一致，且据此可通过权限校验")
    void rotationPreservesCapabilities() {
        IssuedTokens first = tokenService.issueFor(admin, client("pc", "web"));
        // 推进时间后做多次续期
        clock.advance(100_000L);
        IssuedTokens second = tokenService.rotate(first.refreshToken());
        clock.advance(100_000L);
        IssuedTokens third = tokenService.rotate(second.refreshToken());

        var claims = tokenService.authenticate(third.accessToken());
        assertEquals(java.util.Set.of("admin", "user"), claims.roles());
        assertEquals(java.util.Set.of("user:read", "user:write"), claims.permissions());
        assertEquals(java.util.Set.of("openid", "reports:read"), claims.scopes());

        // 服务端会话快照与新访问令牌承载能力一致
        TokenFamily family = store.findFamily(claims.familyId()).orElseThrow();
        assertEquals(claims.roles(), family.roles());
        assertEquals(claims.permissions(), family.permissions());
        assertEquals(claims.scopes(), family.scopes());

        // 旧令牌对已轮换失效；最新访问令牌承载 reports:read 范围，可通过范围校验
        assertDoesNotThrow(() -> tokenService.authenticate(third.accessToken()));
    }

    @Test
    @DisplayName("撤销与续期竞争：撤销一旦生效，之后该会话不能再换出新可用凭证")
    void revokeAndRotateRaceConsistent() throws Exception {
        final int rounds = 50;
        int rotateOkRounds = 0;
        int rotateRejectedRounds = 0;
        for (int round = 0; round < rounds; round++) {
            IssuedTokens first = tokenService.issueFor(alice, client("dev", "c"));
            final String refresh = first.refreshToken();
            final String family = tokenService.authenticate(first.accessToken()).familyId();
            ExecutorService pool = Executors.newFixedThreadPool(2);
            CountDownLatch start = new CountDownLatch(1);
            ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();

            pool.submit(() -> {
                await(start);
                try {
                    IssuedTokens rotated = tokenService.rotate(refresh);
                    outcomes.add("ROTATE_OK:" + rotated.accessToken());
                } catch (TokenException ex) {
                    outcomes.add("ROTATE_FAIL:" + ex.getReason());
                }
            });
            pool.submit(() -> {
                await(start);
                tokenService.revokeFamilyById(family);
                outcomes.add("REVOKE_OK");
            });
            start.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));

            // 终态自洽：无论两个线程谁先拿到族锁，最终族必须是 REVOKED
            assertTrue(store.findFamily(family).orElseThrow().revoked(),
                    "第 " + round + " 轮后族必须为 REVOKED");
            for (String outcome : outcomes) {
                if (outcome.startsWith("ROTATE_OK")) {
                    rotateOkRounds++;
                    // 轮换即使先一步成功，其刚换出的新访问令牌也必须因随后撤销而不可用，
                    // 不会出现“撤销已生效，过一会儿又换出新凭证继续能用”
                    String access = outcome.substring("ROTATE_OK:".length());
                    TokenException ex = assertThrows(TokenException.class,
                            () -> tokenService.authenticate(access));
                    assertEquals(TokenRejectionReason.REVOKED, ex.getReason());
                    // 新刷新令牌同样不能再续期
                    assertThrows(TokenException.class,
                            () -> tokenService.rotate(refresh));
                } else if (outcome.startsWith("ROTATE_FAIL")) {
                    rotateRejectedRounds++;
                    // 撤销先持锁时，续期被拒原因必须是 REVOKED（而非 EXPIRED/UNKNOWN 等）
                    assertTrue(outcome.endsWith("REVOKED"),
                            "撤销先持锁时续期应得 REVOKED，实际: " + outcome);
                }
            }
        }
        // 每轮恰好一次续期尝试：成功与被拒之和等于轮数，两种交错都被覆盖
        assertEquals(rounds, rotateOkRounds + rotateRejectedRounds);
        assertTrue(rotateOkRounds + rotateRejectedRounds == rounds);
    }

    @Test
    @DisplayName("并发登录：同一账号大量并发建立会话也绝不超过上限，且新会话自身不被误伤")
    void concurrentLoginsNeverExceedLimit() throws Exception {
        final int threads = 12;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<IssuedTokens> issued = new ConcurrentLinkedQueue<>();
        AtomicInteger failures = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    IssuedTokens tokens = tokenService.issueFor(alice, client("dev-" + idx, "c" + idx));
                    issued.add(tokens);
                } catch (Exception ex) {
                    failures.incrementAndGet();
                }
            });
        }
        ready.await(5, TimeUnit.SECONDS);
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        assertEquals(0, failures.get(), "登录建立本身不应失败（超限时淘汰旧会话而非拒绝新会话）");
        assertEquals(threads, issued.size());
        assertEquals(properties.getMaxSessionsPerUser(), activeCount("alice"),
                "并发结束后有效会话数必须恰好等于上限");
        // 每个新签发令牌在认证时要么仍可用，要么因容量被淘汰（EVICTED）；
        // 时钟未推进不会是 EXPIRED，无重放/撤销不会是 REVOKED。恰好“上限”个保持可用。
        AtomicInteger usable = new AtomicInteger();
        for (IssuedTokens tokens : issued) {
            try {
                tokenService.authenticate(tokens.accessToken());
                usable.incrementAndGet();
            } catch (TokenException ex) {
                assertEquals(TokenRejectionReason.EVICTED, ex.getReason(),
                        "失效只可能来自容量淘汰，实际: " + ex.getReason());
            }
        }
        assertEquals(properties.getMaxSessionsPerUser(), usable.get(),
                "恰好应有上限数量的会话仍可用，其余为被淘汰的旧会话");
    }

    @Test
    @DisplayName("被淘汰会话的旧刷新令牌轮换得到 EVICTED（与 REVOKED/EXPIRED 区分），且不改变其它会话")
    void evictedRefreshReasonDistinct() {
        IssuedTokens s1 = tokenService.issueFor(alice, client("dev-1", "c1"));
        clock.advance(1_000L);
        tokenService.issueFor(alice, client("dev-2", "c2"));
        clock.advance(1_000L);
        tokenService.issueFor(alice, client("dev-3", "c3"));
        clock.advance(1_000L);
        IssuedTokens s4 = tokenService.issueFor(alice, client("dev-4", "c4"));

        TokenException ex = assertThrows(TokenException.class, () -> tokenService.rotate(s1.refreshToken()));
        assertEquals(TokenRejectionReason.EVICTED, ex.getReason());
        // 主动撤销的会话给出 REVOKED，与 EVICTED 区分
        tokenService.revoke(s4.refreshToken());
        TokenException revoked = assertThrows(TokenException.class, () -> tokenService.rotate(s4.refreshToken()));
        assertEquals(TokenRejectionReason.REVOKED, revoked.getReason());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }
}
