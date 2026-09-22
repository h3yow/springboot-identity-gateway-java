package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.error.ApiException;
import com.github.h3yow.springbootidentitygatewayjava.error.ErrorCode;
import com.github.h3yow.springbootidentitygatewayjava.security.AuthInterceptor;
import com.github.h3yow.springbootidentitygatewayjava.security.Authentication;
import com.github.h3yow.springbootidentitygatewayjava.security.RequireScope;
import com.github.h3yow.springbootidentitygatewayjava.support.MutableTimeProvider;
import com.github.h3yow.springbootidentitygatewayjava.token.AccessTokenStore;
import com.github.h3yow.springbootidentitygatewayjava.token.SessionStore;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenPair;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 访问控制三类拒绝与允许，确保各入口判定一致、默认拒绝：
 * 未认证 TOKEN_*（401）、角色不足 ACCESS_DENIED_ROLE、范围不足 ACCESS_DENIED_SCOPE。
 */
class AuthInterceptorTest {

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptorTest.class);
    private static final Instant T0 = Instant.parse("2026-09-23T00:00:00Z");

    private MutableTimeProvider clock;
    private TokenService tokenService;
    private SessionStore sessionStore;
    private AuthInterceptor interceptor;

    /** 仅用于反射取得带 @RequireScope 的 HandlerMethod。 */
    static class Endpoints {
        @RequireScope
        public void authenticatedOnly() {
        }

        @RequireScope("orders:read")
        public void orders() {
        }

        @RequireScope(value = "admin:write", roles = "admin")
        public void admin() {
        }

        public void unannotated() {
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableTimeProvider(T0);
        AuthProperties props = new AuthProperties();
        props.setAccessTokenTtlSeconds(900);
        props.setRefreshTokenTtlSeconds(1200);
        props.setSessionMaxTtlSeconds(86400);
        sessionStore = new SessionStore();
        AccessTokenStore accessTokenStore = new AccessTokenStore();
        tokenService = new TokenService(props, clock, sessionStore, accessTokenStore);
        interceptor = new AuthInterceptor(tokenService, sessionStore);
    }

    private HandlerMethod handler(String name) throws NoSuchMethodException {
        Method m = Endpoints.class.getMethod(name);
        return new HandlerMethod(new Endpoints(), m);
    }

    private MockHttpServletRequest requestWith(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/resources/x");
        if (token != null) {
            request.addHeader("Authorization", "Bearer " + token);
        }
        return request;
    }

    private ErrorCode invoke(MockHttpServletRequest req, HandlerMethod hm) {
        try {
            boolean ok = interceptor.preHandle(req, new MockHttpServletResponse(), hm);
            assertTrue(ok);
            return null;
        } catch (ApiException e) {
            return e.errorCode();
        }
    }

    private TokenPair issueToken(Set<String> roles, Set<String> scopes) {
        return tokenService.issue("user-" + roles + scopes, roles, scopes);
    }

    @Test
    void unauthenticatedMissingTokenIsRejected() throws Exception {
        MockHttpServletRequest req = requestWith(null);
        ErrorCode code = invoke(req, handler("orders"));
        log.info("[输入] 无 Authorization 头访问 orders [判定依据] 拦截器先要求令牌 -> {}", code);
        assertEquals(ErrorCode.TOKEN_MISSING, code);
    }

    @Test
    void authenticatedWithoutScopeIsRejectedAsScopeDenied() throws Exception {
        TokenPair pair = issueToken(Set.of("user"), Set.of("profile:read"));
        MockHttpServletRequest req = requestWith(pair.accessToken());
        ErrorCode code = invoke(req, handler("orders"));
        log.info("[输入] subjectScopes={} 访问需要 orders:read 的入口 [判定] -> {}",
                Set.of("profile:read"), code);
        assertEquals(ErrorCode.ACCESS_DENIED_SCOPE, code);
    }

    @Test
    void wrongRoleIsRejectedAsRoleDeniedEvenWithScope() throws Exception {
        // 有 admin:write 范围但不是 admin 角色：角色判定先于范围，应给 ROLE 拒绝
        TokenPair pair = issueToken(Set.of("user"), Set.of("admin:write", "orders:read"));
        MockHttpServletRequest req = requestWith(pair.accessToken());
        ErrorCode code = invoke(req, handler("admin"));
        log.info("[输入] roles={} scopes={} 访问需要 admin 角色+admin:write [判定] -> {}",
                Set.of("user"), Set.of("admin:write"), code);
        assertEquals(ErrorCode.ACCESS_DENIED_ROLE, code);
    }

    @Test
    void adminRoleWithoutAdminScopeIsRejectedAsScopeDenied() throws Exception {
        TokenPair pair = issueToken(Set.of("admin"), Set.of("orders:read"));
        MockHttpServletRequest req = requestWith(pair.accessToken());
        ErrorCode code = invoke(req, handler("admin"));
        log.info("[输入] roles=admin 但无 admin:write 范围 [判定] -> {}", code);
        assertEquals(ErrorCode.ACCESS_DENIED_SCOPE, code);
    }

    @Test
    void sufficientRoleAndScopePassesAndPopulatesAuthentication() throws Exception {
        TokenPair pair = issueToken(Set.of("admin", "user"), Set.of("orders:read", "admin:write"));
        MockHttpServletRequest req = requestWith(pair.accessToken());
        ErrorCode code = invoke(req, handler("admin"));
        log.info("[输入] roles={} scopes={} 访问 admin 入口 [判定] -> {} (null 表示放行)",
                Set.of("admin", "user"), Set.of("admin:write"), code);
        assertEquals(null, code);
        Authentication auth = (Authentication) req.getAttribute(AuthInterceptor.AUTH_ATTRIBUTE);
        assertNotNull(auth);
        assertTrue(auth.roles().contains("admin"));
        assertTrue(auth.scopes().contains("admin:write"));
    }

    @Test
    void anyAuthenticatedUserReachesProfile() throws Exception {
        TokenPair pair = issueToken(Set.of(), Set.of());
        MockHttpServletRequest req = requestWith(pair.accessToken());
        ErrorCode code = invoke(req, handler("authenticatedOnly"));
        log.info("[输入] 无角色无范围的已认证主体访问仅需登录入口 [判定] -> {} (null 表示放行)", code);
        assertEquals(null, code);
    }

    @Test
    void unannotatedEndpointIsDeniedByDefault() throws Exception {
        TokenPair pair = issueToken(Set.of("admin"), Set.of("admin:write"));
        MockHttpServletRequest req = requestWith(pair.accessToken());
        ErrorCode code = invoke(req, handler("unannotated"));
        log.info("[输入] 已认证主体访问未标注 @RequireScope 的方法 [判定依据] 默认拒绝 -> {}", code);
        assertEquals(ErrorCode.ACCESS_DENIED_ROLE, code);
    }
}
