package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.session.ClientInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionException;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionFailureReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionService;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionState;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenFamily;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenStore;
import com.github.h3yow.springbootidentitygatewayjava.tests.support.MutableClock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 会话清单与精准撤销的单元测试：
 * 多端并存、属主隔离、撤销/淘汰/过期不出现、能力概要取自会话快照、撤销幂等与属主校验。
 */
class SessionServiceTest {

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private TokenStore store;
    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        store = new TokenStore();
        sessionService = new SessionService(store, clock);
    }

    private TokenFamily activeFamily(String id, String user, long createdAt, long lastActiveAt,
                                     ClientInfo client, Set<String> roles,
                                     Set<String> perms, Set<String> scopes) {
        TokenFamily family = new TokenFamily(id, user, createdAt, lastActiveAt,
                T0 + 600_000L, SessionState.ACTIVE, client, roles, perms, scopes);
        store.saveFamily(family);
        return family;
    }

    @Test
    @DisplayName("同一账号多端并存：清单含全部有效会话并区分设备/客户端与时间")
    void listsMultipleActiveSessionsWithDeviceInfo() {
        activeFamily("fam-phone", "alice", T0, T0,
                new ClientInfo("phone", "iPhone 15", "ios-app"),
                Set.of("user"), Set.of("user:read"), Set.of("openid", "reports:read"));
        clock.advance(10_000L);
        activeFamily("fam-laptop", "alice", clock.nowMillis(), clock.nowMillis(),
                new ClientInfo("laptop", "MacBook Pro", "web-browser"),
                Set.of("user"), Set.of("user:read"), Set.of("openid", "reports:read"));

        List<SessionInfo> sessions = sessionService.listActiveSessions("alice");

        assertEquals(2, sessions.size());
        SessionInfo phone = sessions.get(0);
        assertEquals("fam-phone", phone.sessionId());
        assertEquals("phone", phone.deviceType());
        assertEquals("iPhone 15", phone.deviceName());
        assertEquals("ios-app", phone.clientId());
        assertEquals(T0, phone.createdAt());
        assertEquals(T0, phone.lastActiveAt());
        SessionInfo laptop = sessions.get(1);
        assertEquals("fam-laptop", laptop.sessionId());
        assertEquals("laptop", laptop.deviceType());
        assertEquals("web-browser", laptop.clientId());
        assertEquals(T0 + 10_000L, laptop.createdAt());
    }

    @Test
    @DisplayName("清单按属主隔离：只能看到自己的会话，看不到他人会话")
    void listIsolationByOwner() {
        activeFamily("fam-alice", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid"));
        activeFamily("fam-bob", "bob", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid"));

        assertEquals(1, sessionService.listActiveSessions("alice").size());
        assertEquals("fam-alice", sessionService.listActiveSessions("alice").get(0).sessionId());
        assertEquals(1, sessionService.listActiveSessions("bob").size());
        assertTrue(sessionService.listActiveSessions("nobody").isEmpty());
    }

    @Test
    @DisplayName("已撤销、已淘汰、已过期的会话都不出现在清单里")
    void terminatedAndExpiredSessionsExcluded() {
        TokenFamily alive = activeFamily("fam-alive", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid"));
        TokenFamily revoked = activeFamily("fam-revoked", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid")).asRevoked();
        TokenFamily evicted = activeFamily("fam-evicted", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid")).asEvicted();
        TokenFamily expired = new TokenFamily("fam-expired", "alice", T0, T0,
                T0 - 1L, SessionState.ACTIVE, ClientInfo.unknown(),
                Set.of("user"), Set.of("user:read"), Set.of("openid"));
        store.putFamily(revoked);
        store.putFamily(evicted);
        store.saveFamily(expired);

        List<SessionInfo> sessions = sessionService.listActiveSessions("alice");
        assertEquals(1, sessions.size());
        assertEquals(alive.familyId(), sessions.get(0).sessionId());
    }

    @Test
    @DisplayName("清单能力概要与会话快照一致（续期不会凭空减少能力）")
    void capabilityOverviewComesFromSnapshot() {
        activeFamily("fam-admin", "admin", T0, T0,
                new ClientInfo("tablet", "iPad", "tablet-app"),
                Set.of("admin", "user"), Set.of("user:read", "user:write"),
                Set.of("openid", "reports:read"));

        SessionInfo info = sessionService.listActiveSessions("admin").get(0);
        assertEquals(Set.of("admin", "user"), info.roles());
        assertEquals(Set.of("user:read", "user:write"), info.permissions());
        assertEquals(Set.of("openid", "reports:read"), info.scopes());
    }

    @Test
    @DisplayName("精准撤销：指定会话变 REVOKED 并从清单消失，其它会话不受影响")
    void revokeSingleSessionOnlyAffectsTarget() {
        activeFamily("fam-1", "alice", T0, T0,
                new ClientInfo("phone", null, "ios-app"),
                Set.of("user"), Set.of("user:read"), Set.of("openid"));
        activeFamily("fam-2", "alice", T0 + 1, T0 + 1,
                new ClientInfo("laptop", null, "web"),
                Set.of("user"), Set.of("user:read"), Set.of("openid"));

        SessionState state = sessionService.revokeSession("alice", "fam-1");
        assertEquals(SessionState.REVOKED, state);

        List<SessionInfo> remaining = sessionService.listActiveSessions("alice");
        assertEquals(1, remaining.size());
        assertEquals("fam-2", remaining.get(0).sessionId());
        assertTrue(store.findFamily("fam-1").orElseThrow().revoked());
    }

    @Test
    @DisplayName("重复撤销同一会话：结论一致、不抛异常（幂等）")
    void revokeIsIdempotent() {
        activeFamily("fam-1", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid"));

        SessionState first = sessionService.revokeSession("alice", "fam-1");
        SessionState second = sessionService.revokeSession("alice", "fam-1");
        SessionState third = sessionService.revokeSession("alice", "fam-1");
        assertEquals(SessionState.REVOKED, first);
        assertEquals(SessionState.REVOKED, second);
        assertEquals(SessionState.REVOKED, third);
    }

    @Test
    @DisplayName("不能撤销他人会话：返回 SESSION_NOT_OWNED 且目标会话保持有效")
    void revokeOthersSessionForbidden() {
        activeFamily("fam-alice", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid"));

        SessionException ex = assertThrows(SessionException.class,
                () -> sessionService.revokeSession("bob", "fam-alice"));
        assertEquals(SessionFailureReason.SESSION_NOT_OWNED, ex.getReason());
        assertTrue(store.findFamily("fam-alice").orElseThrow().active());
        // 属主本人仍可正常看到该会话
        assertEquals(1, sessionService.listActiveSessions("alice").size());
    }

    @Test
    @DisplayName("撤销不存在的会话：返回 SESSION_NOT_FOUND")
    void revokeUnknownSession() {
        SessionException ex = assertThrows(SessionException.class,
                () -> sessionService.revokeSession("alice", "missing"));
        assertEquals(SessionFailureReason.SESSION_NOT_FOUND, ex.getReason());
    }

    @Test
    @DisplayName("已被淘汰的会话再次执行撤销：保持 EVICTED 终态，不被改写为 REVOKED（终态先到先得）")
    void revokeDoesNotRewriteEvicted() {
        TokenFamily evicted = activeFamily("fam-ev", "alice", T0, T0,
                ClientInfo.unknown(), Set.of("user"), Set.of("user:read"), Set.of("openid")).asEvicted();
        store.putFamily(evicted);

        SessionState state = sessionService.revokeSession("alice", "fam-ev");
        assertEquals(SessionState.EVICTED, state);
        assertEquals(SessionState.EVICTED, store.findFamily("fam-ev").orElseThrow().state());
    }
}
