package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.ClientInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionState;
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

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * “撤销一旦生效即不可再被激活”并发回归测试。
 *
 * <p>覆盖访问（authenticate）/续期（rotate）与精准撤销（revokeFamilyById）并发交错：
 * 撤销成功返回后，该会话的访问与续期必须一直被拒、会话从清单保持消失，
 * 拒绝结论与容量淘汰 EVICTED、自然过期 EXPIRED 清晰区分，且不波及其它会话。
 *
 * <p>全部使用 {@link MutableClock} 固定/推进时间，不依赖真实等待或睡眠；
 * 线程间只用 CountDownLatch/CyclicBarrier 做确定性汇合点，离线可重复。
 */
class RevocationConcurrencyTest {

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private AuthProperties properties;
    private TokenSigner signer;
    private UserAccount alice;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        properties = new AuthProperties();
        properties.setAccessTokenTtlMillis(900_000L);
        properties.setRefreshTokenTtlMillis(600_000L);
        properties.setMaxSessionsPerUser(10);
        signer = new TokenSigner(properties);
        UserDirectory userDirectory = new UserDirectory(new Pbkdf2PasswordHasher());
        alice = userDirectory.findByUsername("alice").orElseThrow();
    }

    private TokenService serviceWith(TokenStore store) {
        return new TokenService(store, signer, clock, properties);
    }

    // ------------------------------------------------------------------
    // 存储层不变量：终态（REVOKED/EVICTED）单调，不被旧 ACTIVE 快照复活
    // ------------------------------------------------------------------

    @Test
    @DisplayName("存储不变量：携带旧 ACTIVE 快照的覆盖写不能把 REVOKED 写回 ACTIVE，续期仍被拒")
    void putFamilyNeverResurrectsRevokedState() {
        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);
        IssuedTokens tokens = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
        TokenFamily family = store.allFamilies().stream()
                .filter(f -> f.username().equals("alice")).findFirst().orElseThrow();
        TokenFamily staleActiveSnapshot = family;

        service.revokeFamilyById(family.familyId());
        assertEquals(SessionState.REVOKED, store.findFamily(family.familyId()).orElseThrow().state());

        // 旧 ACTIVE 快照覆盖写必须被存储拒绝
        store.putFamily(staleActiveSnapshot.touch(T0 + 1L, family.expiresAt()));
        assertEquals(SessionState.REVOKED, store.findFamily(family.familyId()).orElseThrow().state(),
                "撤销已生效，旧 ACTIVE 快照不得把会话写活");

        // “撤销后又用刷新令牌换新凭证”必须不可能
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> service.rotate(tokens.refreshToken()));
        assertEquals(TokenRejectionReason.REVOKED, rotateEx.getReason());

        // touchIfActive 对终态同样无效
        assertTrue(store.touchIfActive(family.familyId(), T0 + 9L, T0 + 999L)
                .orElseThrow().terminated());
        assertEquals(SessionState.REVOKED, store.findFamily(family.familyId()).orElseThrow().state());
    }

    @Test
    @DisplayName("存储不变量：容量淘汰 EVICTED 不被旧 ACTIVE 快照复活，访问/续期结论保持 EVICTED")
    void putFamilyNeverResurrectsEvictedState() {
        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);
        IssuedTokens victim = service.issueFor(alice, new ClientInfo("dev-1", "d1", "c1"));
        String victimFamilyId = service.authenticate(victim.accessToken()).familyId();
        clock.advance(100L);
        service.issueFor(alice, new ClientInfo("dev-2", "d2", "c2"));
        clock.advance(100L);
        service.issueFor(alice, new ClientInfo("dev-3", "d3", "c3"));
        TokenFamily victimFamily = store.findFamily(victimFamilyId).orElseThrow();
        // 直接置 EVICTED 模拟容量淘汰终态
        store.evictFamily(victimFamilyId);
        assertEquals(SessionState.EVICTED, store.findFamily(victimFamilyId).orElseThrow().state());

        // 旧 ACTIVE 快照覆盖写不能复活，建立时间/最近活跃时间也不被改写
        store.putFamily(victimFamily.touch(T0 + 500L, victimFamily.expiresAt()));
        TokenFamily after = store.findFamily(victimFamilyId).orElseThrow();
        assertEquals(SessionState.EVICTED, after.state());
        assertEquals(victimFamily.createdAt(), after.createdAt());
        assertEquals(victimFamily.lastActiveAt(), after.lastActiveAt());

        TokenException accessEx = assertThrows(TokenException.class,
                () -> service.authenticate(victim.accessToken()));
        assertEquals(TokenRejectionReason.EVICTED, accessEx.getReason());
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> service.rotate(victim.refreshToken()));
        assertEquals(TokenRejectionReason.EVICTED, rotateEx.getReason());
    }

    // ------------------------------------------------------------------
    // 确定性交错（latch 汇合，无睡眠）：访问/撤销在族锁上的两种线性化
    // ------------------------------------------------------------------

    /**
     * 可控阻塞点存储：当名为 {@code authenticate} 的线程首次进入被观察族的族锁临界区时暂停，
     * 直到主线程显式放行。确定性地构造“访问已在族锁内、撤销在锁上排队”的交错。
     */
    static final class InterceptingStore extends TokenStore {
        private final AtomicReference<String> watchedFamily = new AtomicReference<>();
        private final CountDownLatch accessEnteredCritical = new CountDownLatch(1);
        private final CountDownLatch releaseAccess = new CountDownLatch(1);
        private final AtomicBoolean armed = new AtomicBoolean(true);

        void watch(String familyId) {
            watchedFamily.set(familyId);
        }

        void awaitAccessInsideCritical() throws InterruptedException {
            accessEnteredCritical.await();
        }

        void releaseAccessCritical() {
            releaseAccess.countDown();
        }

        @Override
        public <T> T withFamilyLock(String familyId, Function<String, T> action) {
            // 先匹配族与线程名，最后才消费一次性开关：避免无关调用提前把 armed 置 false
            boolean intercept = familyId.equals(watchedFamily.get())
                    && "authenticate".equals(Thread.currentThread().getName())
                    && armed.compareAndSet(true, false);
            if (intercept) {
                return super.withFamilyLock(familyId, fid -> {
                    accessEnteredCritical.countDown();
                    try {
                        releaseAccess.await();
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException(ex);
                    }
                    return action.apply(fid);
                });
            }
            return super.withFamilyLock(familyId, action);
        }
    }

    @Test
    @DisplayName("交错A：访问持族锁、撤销在锁上排队——该次访问可成功，但撤销完成后会话彻底停在 REVOKED")
    void accessHoldingLockThenQueuedRevokeEndsRevoked() throws Exception {
        InterceptingStore store = new InterceptingStore();
        TokenService service = serviceWith(store);
        IssuedTokens tokens = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
        String familyId = service.authenticate(tokens.accessToken()).familyId();
        store.watch(familyId);

        ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "authenticate");
            t.setDaemon(true);
            return t;
        });
        Future<String> accessFuture =
                pool.submit(() -> service.authenticate(tokens.accessToken()).username());
        store.awaitAccessInsideCritical();

        // 访问正持有族锁，撤销只能在锁上排队
        Future<?> revokeFuture = pool.submit(() -> {
            service.revokeFamilyById(familyId);
            return null;
        });

        store.releaseAccessCritical();
        assertEquals("alice", accessFuture.get(5, TimeUnit.SECONDS),
                "这次访问在锁内看到 ACTIVE，允许按成功处理");
        revokeFuture.get(5, TimeUnit.SECONDS);
        pool.shutdownNow();

        // 撤销完成：后续访问/续期一律 REVOKED，状态不再反转
        assertEquals(SessionState.REVOKED, store.findFamily(familyId).orElseThrow().state());
        TokenException nextAccess = assertThrows(TokenException.class,
                () -> service.authenticate(tokens.accessToken()));
        assertEquals(TokenRejectionReason.REVOKED, nextAccess.getReason());
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> service.rotate(tokens.refreshToken()));
        assertEquals(TokenRejectionReason.REVOKED, rotateEx.getReason());
    }

    @Test
    @DisplayName("交错B：撤销先完成、访问随后到达——访问当场 REVOKED，不产生任何活跃写")
    void revokeCompletesFirstThenAccessRejected() {        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);
        IssuedTokens tokens = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
        String familyId = service.authenticate(tokens.accessToken()).familyId();
        TokenFamily before = store.findFamily(familyId).orElseThrow();

        service.revokeFamilyById(familyId);

        TokenException accessEx = assertThrows(TokenException.class,
                () -> service.authenticate(tokens.accessToken()));
        assertEquals(TokenRejectionReason.REVOKED, accessEx.getReason());
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> service.rotate(tokens.refreshToken()));
        assertEquals(TokenRejectionReason.REVOKED, rotateEx.getReason());

        // 被拒访问不得改动终态，也不得把最近活跃时间/建立时间改回可用
        TokenFamily after = store.findFamily(familyId).orElseThrow();
        assertEquals(SessionState.REVOKED, after.state());
        assertEquals(before.createdAt(), after.createdAt());
        assertEquals(before.lastActiveAt(), after.lastActiveAt());
    }

    @Test
    @DisplayName("根因复现（无线程）：访问读到 ACTIVE 后撤销生效，访问的迟到写回不得复活会话，之后访问/续期恒被拒")
    void staleActiveWriteAfterRevokeCannotReactivateSession() {
        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);
        IssuedTokens tokens = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
        String familyId = service.authenticate(tokens.accessToken()).familyId();
        TokenFamily activeSnapshot = store.findFamily(familyId).orElseThrow();
        clock.advance(7_000L);
        long later = clock.nowMillis();

        // 1) 另一台设备把该手机会话精准撤销，接口返回成功、状态 REVOKED
        service.revokeFamilyById(familyId);
        assertEquals(SessionState.REVOKED, store.findFamily(familyId).orElseThrow().state());
        // 2) 手机这边“早先读到 ACTIVE、此刻才把活跃时间写回”（模拟撤销前已开始的在途访问）
        store.putFamily(activeSnapshot.touch(later, activeSnapshot.expiresAt()));

        // 3) 会话必须仍停在 REVOKED，时间戳不被改回可用
        TokenFamily after = store.findFamily(familyId).orElseThrow();
        assertEquals(SessionState.REVOKED, after.state());
        assertEquals(activeSnapshot.lastActiveAt(), after.lastActiveAt(),
                "迟到的 ACTIVE 写回必须被丢弃，不能推进最近活跃时间");

        // 4) 之后该会话的访问与续期一直被拒为 REVOKED，刷不出新凭证
        assertEquals(TokenRejectionReason.REVOKED,
                assertThrows(TokenException.class, () -> service.authenticate(tokens.accessToken())).getReason());
        assertEquals(TokenRejectionReason.REVOKED,
                assertThrows(TokenException.class, () -> service.rotate(tokens.refreshToken())).getReason());
        // 再来一次仍然是 REVOKED，保持消失
        assertEquals(TokenRejectionReason.REVOKED,
                assertThrows(TokenException.class, () -> service.authenticate(tokens.accessToken())).getReason());
    }

    // ------------------------------------------------------------------
    // 多轮真并发压力：访问线程 + 续期线程 与 撤销线程同时发起，反复跑结论恒定
    // ------------------------------------------------------------------
    @Test
    @DisplayName("多轮并发：多个访问线程与续期线程同撤销并发，撤销后状态恒为 REVOKED 且新凭证全不可用")
    void concurrentAccessAndRotateAgainstRevokeAlwaysSettlesRevoked() throws Exception {
        final int rounds = 100;
        final int accessThreads = 8;
        for (int round = 0; round < rounds; round++) {
            TokenStore store = new TokenStore();
            TokenService service = serviceWith(store);
            // 同账号另一台设备：验证修复绝不波及其它会话
            IssuedTokens siblingTokens = service.issueFor(alice, new ClientInfo("laptop", "lap", "web"));
            String siblingId = service.authenticate(siblingTokens.accessToken()).familyId();

            IssuedTokens tokens = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
            String familyId = service.authenticate(tokens.accessToken()).familyId();
            // 推进时钟：撤销前成功的访问会把活跃时间推进到该时刻（合法线性化）；
            // 而“撤销后又被成功访问写活”会推进到更晚时刻，从而被后续断言抓到
            clock.advance(5_000L);

            int totalThreads = accessThreads + 2; // 访问线程 + 1 续期 + 1 撤销
            CyclicBarrier barrier = new CyclicBarrier(totalThreads);
            ExecutorService pool = Executors.newFixedThreadPool(totalThreads);
            ConcurrentLinkedQueue<String> outcomes = new ConcurrentLinkedQueue<>();
            AtomicReference<IssuedTokens> rotatedIfAny = new AtomicReference<>();

            for (int i = 0; i < accessThreads; i++) {
                pool.submit(() -> {
                    barrier.await();
                    try {
                        service.authenticate(tokens.accessToken());
                        outcomes.add("ACCESS_OK");
                    } catch (TokenException ex) {
                        outcomes.add("ACCESS_FAIL:" + ex.getReason());
                    }
                    return null;
                });
            }
            Future<?> rotateFuture = pool.submit(() -> {
                barrier.await();
                try {
                    rotatedIfAny.set(service.rotate(tokens.refreshToken()));
                    outcomes.add("ROTATE_OK");
                } catch (TokenException ex) {
                    outcomes.add("ROTATE_FAIL:" + ex.getReason());
                }
                return null;
            });
            Future<?> revokeFuture = pool.submit(() -> {
                barrier.await();
                service.revokeFamilyById(familyId);
                outcomes.add("REVOKE_OK");
                return null;
            });

            rotateFuture.get(5, TimeUnit.SECONDS);
            revokeFuture.get(5, TimeUnit.SECONDS);
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS), "第 " + round + " 轮线程未按时结束");

            // 撤销已完成：记录此刻的终态时间戳。撤销之前成功的访问/续期允许把活跃时间推进到
            // T0+5000（这是合法线性化）；但撤销完成之后的任何操作都不得再改动它。
            TokenFamily settled = store.findFamily(familyId).orElseThrow();
            assertEquals(SessionState.REVOKED, settled.state(),
                    "第 " + round + " 轮终态必须是 REVOKED，outcomes=" + outcomes);
            long settledLastActiveAt = settled.lastActiveAt();
            long settledCreatedAt = settled.createdAt();

            // 再推进时钟：撤销后若访问被错误放行，touch 会写进更晚的 lastActiveAt/复活为 ACTIVE
            clock.advance(9_000L);

            // 不变量1：原访问令牌与原刷新令牌此后一律 REVOKED
            TokenException accessEx = assertThrows(TokenException.class,
                    () -> service.authenticate(tokens.accessToken()));
            assertEquals(TokenRejectionReason.REVOKED, accessEx.getReason());
            TokenException rotateEx = assertThrows(TokenException.class,
                    () -> service.rotate(tokens.refreshToken()));
            assertEquals(TokenRejectionReason.REVOKED, rotateEx.getReason());

            // 不变量2：撤销完成后状态与建立/最近活跃时间纹丝不动，不被“改回可用”
            TokenFamily finalFamily = store.findFamily(familyId).orElseThrow();
            assertEquals(SessionState.REVOKED, finalFamily.state(), "终态不得自行反转");
            assertEquals(settledCreatedAt, finalFamily.createdAt());
            assertEquals(settledLastActiveAt, finalFamily.lastActiveAt(),
                    "撤销完成后最近活跃时间不得再被推进，第 " + round + " 轮");

            // 不变量3：若续期先一步换出新凭证，这对新凭证也必须因随后撤销立即失效且不可再续期
            IssuedTokens rotated = rotatedIfAny.get();
            if (rotated != null) {
                TokenException newAccessEx = assertThrows(TokenException.class,
                        () -> service.authenticate(rotated.accessToken()));
                assertEquals(TokenRejectionReason.REVOKED, newAccessEx.getReason());
                TokenException newRotateEx = assertThrows(TokenException.class,
                        () -> service.rotate(rotated.refreshToken()));
                assertEquals(TokenRejectionReason.REVOKED, newRotateEx.getReason());
            }

            // 不变量4：竞争期间访问/续期的失败结论只可能是 REVOKED（时钟未过期、未触发淘汰）
            for (String outcome : outcomes) {
                if (outcome.startsWith("ACCESS_FAIL")) {
                    assertTrue(outcome.endsWith("REVOKED"),
                            "访问失败原因必须是 REVOKED，实际: " + outcome);
                }
                if (outcome.startsWith("ROTATE_FAIL")) {
                    assertTrue(outcome.endsWith("REVOKED"),
                            "续期失败原因必须是 REVOKED，实际: " + outcome);
                }
            }

            // 不变量5：同账号其它设备会话照常可用，终态 ACTIVE，不被连带
            assertEquals(SessionState.ACTIVE, store.findFamily(siblingId).orElseThrow().state());
            assertDoesNotThrow(() -> service.authenticate(siblingTokens.accessToken()));
            assertDoesNotThrow(() -> service.rotate(siblingTokens.refreshToken()));
        }
    }

    // ------------------------------------------------------------------
    // 顺序确定性场景：续期与撤销的两种先后，结论都自洽
    // ------------------------------------------------------------------

    @Test
    @DisplayName("续期先成功、撤销后到：新换出的访问/刷新令牌立即 REVOKED，不能再续期")
    void rotateSucceedsThenRevokeInvalidatesNewPair() {
        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);
        IssuedTokens first = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
        String familyId = service.authenticate(first.accessToken()).familyId();

        IssuedTokens second = service.rotate(first.refreshToken());
        service.revokeFamilyById(familyId);

        assertEquals(SessionState.REVOKED, store.findFamily(familyId).orElseThrow().state());
        TokenException accessEx = assertThrows(TokenException.class,
                () -> service.authenticate(second.accessToken()));
        assertEquals(TokenRejectionReason.REVOKED, accessEx.getReason());
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> service.rotate(second.refreshToken()));
        assertEquals(TokenRejectionReason.REVOKED, rotateEx.getReason());
        // 旧刷新令牌也不能借任何路径复活
        assertThrows(TokenException.class, () -> service.rotate(first.refreshToken()));
    }

    @Test
    @DisplayName("撤销先到、续期后到：续期当场 REVOKED，不签发任何新凭证")
    void revokeFirstThenRotateRejectedAndNoNewTokens() {
        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);
        IssuedTokens first = service.issueFor(alice, new ClientInfo("phone", "p", "ios"));
        String familyId = service.authenticate(first.accessToken()).familyId();
        long refreshRecordsBefore = store.allFamilies().size();

        service.revokeFamilyById(familyId);
        TokenException rotateEx = assertThrows(TokenException.class,
                () -> service.rotate(first.refreshToken()));
        assertEquals(TokenRejectionReason.REVOKED, rotateEx.getReason());

        // 再次确认：被撤销后无论重试多少次访问/续期，终态与时间戳都稳定不反转
        TokenFamily snapshot = store.findFamily(familyId).orElseThrow();
        for (int i = 0; i < 5; i++) {
            assertThrows(TokenException.class, () -> service.authenticate(first.accessToken()));
            assertThrows(TokenException.class, () -> service.rotate(first.refreshToken()));
        }
        TokenFamily after = store.findFamily(familyId).orElseThrow();
        assertEquals(SessionState.REVOKED, after.state());
        assertEquals(snapshot.createdAt(), after.createdAt());
        assertEquals(snapshot.lastActiveAt(), after.lastActiveAt());
        assertEquals(refreshRecordsBefore, store.allFamilies().size(),
                "被拒续期不得新建任何会话");
    }

    @Test
    @DisplayName("三类拒绝结论清晰可分：撤销=REVOKED、淘汰=EVICTED、自然过期=EXPIRED，互不串味")
    void rejectionReasonsStayDistinct() {
        TokenStore store = new TokenStore();
        TokenService service = serviceWith(store);

        IssuedTokens revokedTokens = service.issueFor(alice, new ClientInfo("dev-1", "d1", "c1"));
        String revokedId = service.authenticate(revokedTokens.accessToken()).familyId();
        service.revokeFamilyById(revokedId);
        clock.advance(1L);
        IssuedTokens evictedTokens = service.issueFor(alice, new ClientInfo("dev-2", "d2", "c2"));
        clock.advance(1L);
        IssuedTokens expiredTokens = service.issueFor(alice, new ClientInfo("dev-3", "d3", "c3"));

        // 淘汰一个
        String evictedId = service.authenticate(evictedTokens.accessToken()).familyId();
        store.evictFamily(evictedId);

        assertEquals(TokenRejectionReason.REVOKED,
                assertThrows(TokenException.class, () -> service.authenticate(revokedTokens.accessToken())).getReason());
        assertEquals(TokenRejectionReason.EVICTED,
                assertThrows(TokenException.class, () -> service.authenticate(evictedTokens.accessToken())).getReason());

        // 自然过期：推进到访问令牌与刷新令牌均过期
        clock.advance(900_000L);
        assertEquals(TokenRejectionReason.EXPIRED,
                assertThrows(TokenException.class, () -> service.authenticate(expiredTokens.accessToken())).getReason());
        clock.advance(1L);
        assertEquals(TokenRejectionReason.EXPIRED,
                assertThrows(TokenException.class, () -> service.rotate(expiredTokens.refreshToken())).getReason());
    }
}
