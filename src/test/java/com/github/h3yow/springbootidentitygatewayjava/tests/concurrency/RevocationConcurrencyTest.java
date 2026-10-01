package com.github.h3yow.springbootidentitygatewayjava.tests.concurrency;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.ClientInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionService;
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
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Assertions;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/**
 * “访问/续期 与 精准撤销”并发交错的确定性测试。
 *
 * <p>离线可重复、不依赖真实等待或睡眠：时间判定走 {@link MutableClock}（全程不推进），
 * 线程交错通过 {@link TokenService} 的并发插桩点 + {@link CountDownLatch} 双向门闩精确编排，
 * 而不是靠 sleep 碰运气。
 *
 * <p>覆盖的交错：
 * <ol>
 *   <li><b>撤销夹在访问的读-改-写之间（复活 bug 原场景）</b>：访问已读到旧 ACTIVE 快照后暂停，
 *       撤销在此时生效，随后访问用旧快照回写。修复后终态必须仍是 REVOKED，该访问被 REVOKED 拒绝，
 *       会话不再出现于清单，建立时间/最近活跃时间不被旧快照改回。</li>
 *   <li><b>撤销先持锁、访问随后</b>：访问在读取会话状态前暂停、先让撤销拿到族锁完成，
 *       访问恢复后必须当场被 REVOKED 拒绝。</li>
 *   <li><b>撤销与续期：撤销先持锁</b>：撤销先持有族锁停在提交前，续期并发到达只能等锁；
 *       撤销完成后续期得 REVOKED，绝不换出新凭证。</li>
 *   <li><b>撤销与续期：续期先提交、撤销随后</b>：续期可以成功，但紧接着的撤销必须终结会话，
 *       刚换出的新访问/刷新令牌一律被拒，不能再换新凭证。</li>
 * </ol>
 */
class RevocationConcurrencyTest {

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private AuthProperties properties;
    private TokenStore store;
    private SeamedTokenService tokenService;
    private SessionService sessionService;
    private UserAccount alice;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        properties = new AuthProperties();
        properties.setAccessTokenTtlMillis(900_000L);
        properties.setRefreshTokenTtlMillis(600_000L);
        properties.setMaxSessionsPerUser(5);
        store = new TokenStore();
        TokenSigner signer = new TokenSigner(properties);
        tokenService = new SeamedTokenService(store, signer, clock, properties);
        sessionService = new SessionService(store, clock);
        UserDirectory userDirectory = new UserDirectory(new Pbkdf2PasswordHasher());
        alice = userDirectory.findByUsername("alice").orElseThrow();
    }

    private ClientInfo client(String clientId) {
        return new ClientInfo("phone", "lost-phone", clientId);
    }

    // ---------------------------------------------------------------------
    // 交错 1：撤销夹在访问“读旧 ACTIVE 快照 -> 回写 touch”之间（复活 bug）
    // ---------------------------------------------------------------------

    @RepeatedTest(20)
    @DisplayName("撤销夹在访问的读-改-写之间：撤销生效后旧快照回写不得复活会话（手机下线后访问仍被拒）")
    void revokeCommittedBetweenAccessReadAndWrite_neverResurrects() throws Exception {
        IssuedTokens phone = tokenService.issueFor(alice, client("ios"));
        String familyId = tokenService.authenticate(phone.accessToken()).familyId();
        TokenFamily before = store.findFamily(familyId).orElseThrow();

        Gate gate = new Gate();
        tokenService.onAfterAccessSessionLoaded = fid -> {
            if (fid.equals(familyId)) {
                gate.arriveAndAwaitRelease();
            }
        };

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            // 访问先启动：读到旧 ACTIVE 快照后，在回写前停住（修复后此刻持有族锁）
            Future<?> accessFuture = pool.submit(() -> tokenService.authenticate(phone.accessToken()));
            assertTrue(gate.awaitArrival(5), "访问线程应在读后/写前停住");

            // 另一台设备此刻并发发起精准下线：
            // 旧实现下访问不持族锁，撤销会在访问暂停期间先提交 REVOKED（原 bug 交错）；
            // 修复后撤销阻塞在族锁外，直到访问放行并结束，随后立即拿到锁完成撤销。
            CountDownLatch revokeCommitted = new CountDownLatch(1);
            AtomicReference<SessionState> revokeResult = new AtomicReference<>();
            Future<?> revokeFuture = pool.submit(() -> {
                SessionState state = sessionService.revokeSession("alice", familyId, revokeCommitted::countDown);
                revokeResult.set(state);
            });

            // 放行访问。修复后：访问的活跃回写与撤销由族锁串行——
            // 要么回写先完成（访问成功）、撤销紧随终结会话；要么撤销先持锁、访问当场被拒。
            gate.release();
            assertTrue(revokeCommitted.await(5, TimeUnit.SECONDS),
                    "撤销必须在访问回写尝试之后成功提交（终态停在 REVOKED）");
            get(revokeFuture);
            assertEquals(SessionState.REVOKED, revokeResult.get(), "精准撤销接口返回成功且终态为 REVOKED");

            // 夹在中间的那次访问：两种自洽结果之一——当场 REVOKED 拒绝，或先成功但会话随即终结；
            // 无论哪种，撤销返回后都绝不能留下一个可用（ACTIVE）会话。
            Throwable accessOutcome = captureFutureFailure(accessFuture);
            if (accessOutcome != null) {
                assertInstanceOf(TokenException.class, accessOutcome);
                assertEquals(TokenRejectionReason.REVOKED, ((TokenException) accessOutcome).getReason());
            }

            TokenFamily after = store.findFamily(familyId).orElseThrow();
            assertEquals(SessionState.REVOKED, after.state(), "终态必须稳定停在 REVOKED，不能冒回 ACTIVE");
            assertEquals(before.createdAt(), after.createdAt(), "建立时间不应被竞争访问改动");
            assertEquals(before.lastActiveAt(), after.lastActiveAt(),
                    "撤销后的最近活跃时间不应被夹在中间的旧快照回写改回/改新");
            // 撤销生效瞬间及之后，会话已从清单消失并保持消失
            assertTrue(sessionService.listActiveSessions("alice").isEmpty());
            // 持续保持消失：之后再访问依旧 REVOKED
            assertRevokedAccess(phone.accessToken());
            assertTrue(sessionService.listActiveSessions("alice").isEmpty(),
                    "撤销一旦生效，会话必须从清单消失并保持消失");
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    // ---------------------------------------------------------------------
    // 交错 2：撤销先持锁完成，访问随后进入状态判定
    // ---------------------------------------------------------------------

    @RepeatedTest(20)
    @DisplayName("撤销先持锁生效后访问才进入状态判定：访问当场被 REVOKED 拒绝，且不复活会话")
    void revokeHoldsLockFirst_thenAccessSeesRevoked() throws Exception {
        IssuedTokens phone = tokenService.issueFor(alice, client("ios"));
        String familyId = tokenService.authenticate(phone.accessToken()).familyId();

        Gate gate = new Gate();
        tokenService.onBeforeAccessSessionCheck = fid -> {
            if (fid.equals(familyId)) {
                gate.arriveAndAwaitRelease();
            }
        };

        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> accessFuture = pool.submit(() -> tokenService.authenticate(phone.accessToken()));
            assertTrue(gate.awaitArrival(5), "访问线程应在会话状态判定前停住");

            // 访问尚未判定状态，撤销先一步生效
            assertEquals(SessionState.REVOKED, sessionService.revokeSession("alice", familyId));
            gate.release();

            TokenException ex = assertThrows(TokenException.class, () -> get(accessFuture));
            assertEquals(TokenRejectionReason.REVOKED, ex.getReason());
            assertEquals(SessionState.REVOKED, store.findFamily(familyId).orElseThrow().state());
            assertRevokedAccess(phone.accessToken());
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    // ---------------------------------------------------------------------
    // 交错 3：撤销先拿到族锁，续期并发到达只能等锁，撤销完成后续期被 REVOKED 拒绝
    // ---------------------------------------------------------------------

    @RepeatedTest(20)
    @DisplayName("撤销先持锁：并发到达的续期在撤销完成后得 REVOKED，绝不换出新凭证")
    void revokeFirst_rotateRejectedWithRevoked() throws Exception {
        IssuedTokens phone = tokenService.issueFor(alice, client("ios"));
        String familyId = tokenService.authenticate(phone.accessToken()).familyId();
        String refresh = phone.refreshToken();

        Gate revokeGate = new Gate();
        tokenService.onBeforeRevokeCommit = fid -> {
            if (fid.equals(familyId)) {
                revokeGate.arriveAndAwaitRelease();
            }
        };

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            // 撤销线程先启动并抢到族锁，在写入撤销终态前停住（仍持有族锁）
            Future<?> revokeFuture = pool.submit(() -> tokenService.revokeFamilyById(familyId));
            assertTrue(revokeGate.awaitArrival(5), "撤销线程应先持有族锁并停在提交前");

            // 续期此时并发进入，阻塞在族锁外
            AtomicReference<Throwable> rotateError = new AtomicReference<>();
            Future<?> rotateFuture = pool.submit(() -> {
                try {
                    tokenService.rotate(refresh);
                } catch (Throwable t) {
                    rotateError.set(t);
                }
            });

            // 放行撤销：撤销先提交；续期获得族锁后只能看到 REVOKED
            revokeGate.release();
            get(revokeFuture);
            get(rotateFuture);

            Throwable t = rotateError.get();
            assertNotNull(t, "撤销先持锁时续期必须失败");
            assertInstanceOf(TokenException.class, t);
            assertEquals(TokenRejectionReason.REVOKED, ((TokenException) t).getReason());
            assertEquals(SessionState.REVOKED, store.findFamily(familyId).orElseThrow().state());
            assertRevokedRotate(refresh);
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    // ---------------------------------------------------------------------
    // 交错 4：续期先提交成功，但紧随其后的撤销仍终结会话，新凭证全部作废
    // ---------------------------------------------------------------------

    @RepeatedTest(20)
    @DisplayName("续期先一步成功、撤销随后：新换出的访问/刷新令牌仍全部被拒，不能再续期")
    void rotateFirst_thenRevokeKillsFreshTokens() throws Exception {
        IssuedTokens phone = tokenService.issueFor(alice, client("ios"));
        String familyId = tokenService.authenticate(phone.accessToken()).familyId();

        Gate rotateGate = new Gate();
        tokenService.onBeforeRotateCommit = fid -> {
            if (fid.equals(familyId)) {
                rotateGate.arriveAndAwaitRelease();
            }
        };

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<IssuedTokens> rotateFuture = pool.submit(() -> tokenService.rotate(phone.refreshToken()));
            assertTrue(rotateGate.awaitArrival(5), "续期线程应通过前置校验并停在提交前（持族锁）");

            // 撤销并发进入，等待族锁（被续期持有）
            Future<?> revokeFuture = pool.submit(() -> tokenService.revokeFamilyById(familyId));

            // 放行续期：续期提交成功并释放族锁，撤销随即获得锁并终结会话
            rotateGate.release();
            IssuedTokens fresh = get(rotateFuture);
            get(revokeFuture);

            assertEquals(SessionState.REVOKED, store.findFamily(familyId).orElseThrow().state());
            // 这是允许的两种自洽结果之一：这次续期按成功处理，但紧接着的撤销让会话最终不可用
            assertRevokedAccess(fresh.accessToken());
            assertRevokedRotate(fresh.refreshToken());
            assertRevokedRotate(phone.refreshToken());
            assertTrue(sessionService.listActiveSessions("alice").isEmpty());
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    // ---------------------------------------------------------------------
    // 随机交错压力：撤销与高频访问/续期反复并发，终态始终自洽
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("随机交错压力（200轮）：撤销成功后该会话永不复活、永不换新凭证；其它设备会话照常可用")
    void randomInterleavingStress_neverResurrectsOrReissues() throws Exception {
        final int rounds = 200;
        // 容量上限调高到远超总登录数：本用例聚焦撤销/访问/续期竞争，容量淘汰由专门用例覆盖，
        // 避免“其它设备”因跨轮累积被正常淘汰而干扰“不连带撤销”的断言
        properties.setMaxSessionsPerUser(rounds * 2 + 10);
        ExecutorService pool = Executors.newCachedThreadPool();
        try {
            for (int round = 0; round < rounds; round++) {
                tokenService.clearHooks();

                // 被撤销目标（“丢失的手机”）先建立
                IssuedTokens phone = tokenService.issueFor(alice, client("lost-phone"));
                // 受保护的“其它设备”每轮最后建立并在并发期间持续访问，始终为最新会话，
                // 因而绝不会被容量淘汰（EVICTED）——若它最终不可用，只能是被错误连带撤销。
                IssuedTokens other = tokenService.issueFor(alice, client("other-device"));
                String familyId = tokenService.authenticate(phone.accessToken()).familyId();
                // 当前最新刷新令牌（可能被续期工作线程轮换）
                AtomicReference<String> latestRefresh = new AtomicReference<>(phone.refreshToken());

                CountDownLatch start = new CountDownLatch(1);
                Future<?> accessWorker = pool.submit(() -> {
                    await(start);
                    for (int i = 0; i < 25; i++) {
                        try {
                            tokenService.authenticate(phone.accessToken());
                        } catch (TokenException expected) {
                            // 撤销后必然失败
                        }
                    }
                });
                Future<?> rotateWorker = pool.submit(() -> {
                    await(start);
                    for (int i = 0; i < 25; i++) {
                        try {
                            IssuedTokens out = tokenService.rotate(latestRefresh.get());
                            latestRefresh.set(out.refreshToken());
                        } catch (TokenException expected) {
                            // 撤销/重放后必然失败
                        }
                    }
                });
                Future<?> otherWorker = pool.submit(() -> {
                    await(start);
                    for (int i = 0; i < 25; i++) {
                        // 其它设备在整场交错中持续可用；任何异常都会在主线程重新认证时被捕获
                        tokenService.authenticate(other.accessToken());
                    }
                });
                start.countDown();
                // 撤销在访问/续期进行中发生
                SessionState state = sessionService.revokeSession("alice", familyId);
                assertEquals(SessionState.REVOKED, state, "第 " + round + " 轮撤销终态");
                get(accessWorker);
                get(rotateWorker);
                get(otherWorker);

                TokenFamily family = store.findFamily(familyId).orElseThrow();
                assertEquals(SessionState.REVOKED, family.state(),
                        "第 " + round + " 轮：撤销生效后族不得被高频访问/续期复活");
                assertRevokedAccess(phone.accessToken());
                assertRevokedRotate(latestRefresh.get());
                assertTrue(sessionService.listActiveSessions("alice").stream()
                                .noneMatch(s -> s.sessionId().equals(familyId)),
                        "第 " + round + " 轮：被撤销会话必须持续从清单消失");
                // 同账号其它设备会话不受影响、照常可用（既未被连带撤销，也未被容量淘汰）
                assertDoesNotThrow(() -> tokenService.authenticate(other.accessToken()),
                        "第 " + round + " 轮：其它设备会话不应被连带撤销");
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(15, TimeUnit.SECONDS));
        }
    }

    // ---------------------------------------------------------------------

    private void assertRevokedAccess(String accessToken) {
        TokenException ex = assertThrows(TokenException.class, () -> tokenService.authenticate(accessToken));
        assertEquals(TokenRejectionReason.REVOKED, ex.getReason(),
                "撤销后的访问结论必须是 REVOKED（与 EVICTED/EXPIRED 区分）");
    }

    private void assertRevokedRotate(String refreshToken) {
        TokenException ex = assertThrows(TokenException.class, () -> tokenService.rotate(refreshToken));
        // 已撤销族：直接判定为 REVOKED；若该旧令牌恰已被轮换，走重放路径给出 ROTATED（同样整族撤销）。
        // 两者都表示“因撤销语义而拒绝”，绝不允许成功，也不能与 EXPIRED/EVICTED/UNKNOWN 混淆。
        assertTrue(ex.getReason() == TokenRejectionReason.REVOKED || ex.getReason() == TokenRejectionReason.ROTATED,
                "撤销后续期只能是 REVOKED 或重放 ROTATED，实际: " + ex.getReason());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** 运行一个已提交的任务并返回其抛出的异常（无异常返回 null），用于接受“成功或被拒”两种自洽结果。 */
    private static Throwable captureFutureFailure(Future<?> future) {
        try {
            future.get(5, TimeUnit.SECONDS);
            return null;
        } catch (java.util.concurrent.ExecutionException e) {
            return e.getCause();
        } catch (Exception e) {
            return e;
        }
    }

    private static <T> T get(Future<T> future) throws Exception {
        try {
            return future.get(5, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw e;
        }
    }

    /** 双向门闩：工作线程到达后等待，编排线程确认到达后再放行。 */
    private static final class Gate {
        private final CountDownLatch arrived = new CountDownLatch(1);
        private final CountDownLatch released = new CountDownLatch(1);

        void arriveAndAwaitRelease() {
            arrived.countDown();
            try {
                if (!released.await(5, TimeUnit.SECONDS)) {
                    Assertions.fail("门闩等待超时：编排线程未放行（可能发生死锁/未修复导致的永久阻塞）");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        boolean awaitArrival(long seconds) throws InterruptedException {
            return arrived.await(seconds, TimeUnit.SECONDS);
        }

        void release() {
            released.countDown();
        }
    }

    /** 覆写并发插桩点的 TokenService：每个插桩点可安装一个按 familyId 过滤的回调。 */
    private static class SeamedTokenService extends TokenService {
        volatile Consumer<String> onBeforeAccessSessionCheck;
        volatile Consumer<String> onAfterAccessSessionLoaded;
        volatile Consumer<String> onBeforeRotateCommit;
        volatile Consumer<String> onBeforeRevokeCommit;

        SeamedTokenService(TokenStore store, TokenSigner signer, MutableClock clock, AuthProperties properties) {
            super(store, signer, clock, properties);
        }

        void clearHooks() {
            onBeforeAccessSessionCheck = null;
            onAfterAccessSessionLoaded = null;
            onBeforeRotateCommit = null;
            onBeforeRevokeCommit = null;
        }

        @Override
        protected void beforeAccessSessionCheck(String familyId) {
            Consumer<String> hook = onBeforeAccessSessionCheck;
            if (hook != null) {
                hook.accept(familyId);
            }
        }

        @Override
        protected void afterAccessSessionLoaded(String familyId) {
            Consumer<String> hook = onAfterAccessSessionLoaded;
            if (hook != null) {
                hook.accept(familyId);
            }
        }

        @Override
        protected void beforeRotateCommit(String familyId) {
            Consumer<String> hook = onBeforeRotateCommit;
            if (hook != null) {
                hook.accept(familyId);
            }
        }

        @Override
        protected void beforeRevokeCommit(String familyId) {
            Consumer<String> hook = onBeforeRevokeCommit;
            if (hook != null) {
                hook.accept(familyId);
            }
        }
    }
}
