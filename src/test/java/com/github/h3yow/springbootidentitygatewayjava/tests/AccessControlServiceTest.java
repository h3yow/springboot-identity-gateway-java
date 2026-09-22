package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.github.h3yow.springbootidentitygatewayjava.auth.access.AccessControlService;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.AccessDecision;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.AccessDenialReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.RequireAccess;
import com.github.h3yow.springbootidentitygatewayjava.auth.credential.Pbkdf2PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.IssuedTokens;
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * 访问控制边界测试，三类结论必须可区分：
 * UNAUTHENTICATED / FORBIDDEN_NO_PERMISSION / FORBIDDEN_INSUFFICIENT_SCOPE。
 */
class AccessControlServiceTest {

    private static final Logger log = LoggerFactory.getLogger(AccessControlServiceTest.class);

    private static final long T0 = 1_700_000_000_000L;

    private MutableClock clock;
    private TokenService tokenService;
    private AccessControlService accessControlService;
    private UserDirectory userDirectory;

    /** 测试用要求声明，避免依赖注解反射。 */
    private RequireAccess none;
    private RequireAccess adminArea;
    private RequireAccess reportsArea;

    @BeforeEach
    void setUp() throws Exception {
        clock = new MutableClock(T0);
        AuthProperties properties = new AuthProperties();
        TokenStore store = new TokenStore();
        TokenSigner signer = new TokenSigner(properties);
        tokenService = new TokenService(store, signer, clock, properties);
        accessControlService = new AccessControlService(tokenService);
        userDirectory = new UserDirectory(new Pbkdf2PasswordHasher());

        none = SampleRequirements.class.getDeclaredField("NONE").getAnnotation(RequireAccess.class);
        adminArea = SampleRequirements.class.getDeclaredField("ADMIN_AREA").getAnnotation(RequireAccess.class);
        reportsArea = SampleRequirements.class.getDeclaredField("REPORTS_AREA").getAnnotation(RequireAccess.class);
    }

    /** 仅用于以类型安全方式持有注解实例。 */
    static class SampleRequirements {
        @RequireAccess
        String NONE;
        @RequireAccess(roles = {"admin"}, permissions = {"user:write"})
        String ADMIN_AREA;
        @RequireAccess(scopes = {"reports:read"})
        String REPORTS_AREA;
    }

    private String bearerFor(String username) {
        UserAccount account = userDirectory.findByUsername(username).orElseThrow();
        IssuedTokens tokens = tokenService.issueFor(account);
        return "Bearer " + tokens.accessToken();
    }

    @Test
    @DisplayName("无 Authorization 头：UNAUTHENTICATED")
    void missingHeader() {
        log.info("输入: authorizationHeader=null, 要求=@RequireAccess(仅认证)");
        AccessDecision decision = accessControlService.decide(null, none);
        log.info("判定依据: 缺少 Bearer 令牌 -> allowed={}, reason={}", decision.allowed(), decision.denialReason());
        assertFalse(decision.allowed());
        assertEquals(AccessDenialReason.UNAUTHENTICATED, decision.denialReason());
    }

    @Test
    @DisplayName("格式错误的头：UNAUTHENTICATED")
    void malformedHeader() {
        log.info("输入: authorizationHeader=Basic abc, 要求=@RequireAccess(仅认证)");
        AccessDecision decision = accessControlService.decide("Basic abc", none);
        assertEquals(AccessDenialReason.UNAUTHENTICATED, decision.denialReason());
        log.info("判定依据: 非 Bearer 方案 -> reason={}", decision.denialReason());
    }

    @Test
    @DisplayName("过期/撤销令牌：UNAUTHENTICATED（与无权限明确区分）")
    void expiredToken() {
        UserAccount alice = userDirectory.findByUsername("alice").orElseThrow();
        IssuedTokens tokens = tokenService.issueFor(alice);
        clock.advance(10_000_000L);
        log.info("输入: 已过期访问令牌, 要求=@RequireAccess(仅认证), now={}", clock.nowMillis());
        AccessDecision decision = accessControlService.decide("Bearer " + tokens.accessToken(), none);
        log.info("判定依据: 令牌 EXPIRED -> reason={}", decision.denialReason());
        assertFalse(decision.allowed());
        assertEquals(AccessDenialReason.UNAUTHENTICATED, decision.denialReason());
    }

    @Test
    @DisplayName("已认证但无角色/权限：FORBIDDEN_NO_PERMISSION")
    void authenticatedButNoPermission() {
        String header = bearerFor("bob");
        log.info("输入: user=bob(roles=[user],perms=[user:read]), 要求 roles=[admin] 或 perms=[user:write]");
        AccessDecision decision = accessControlService.decide(header, adminArea);
        log.info("判定依据: roleOk=false 且 permOk=false -> reason={}, rationale={}",
                decision.denialReason(), decision.rationale());
        assertFalse(decision.allowed());
        assertEquals(AccessDenialReason.FORBIDDEN_NO_PERMISSION, decision.denialReason());
    }

    @Test
    @DisplayName("admin 角色或 user:write 权限满足时放行")
    void permissionSatisfiedByRoleOrPermission() {
        log.info("输入: user=admin, 要求 roles=[admin] 或 perms=[user:write]");
        AccessDecision asAdmin = accessControlService.decide(bearerFor("admin"), adminArea);
        assertTrue(asAdmin.allowed(), "admin 应可访问管理区: " + asAdmin.rationale());

        // alice 无 admin 角色也无 user:write，被拒绝
        AccessDecision asAlice = accessControlService.decide(bearerFor("alice"), adminArea);
        log.info("alice 判定: reason={}", asAlice.denialReason());
        assertEquals(AccessDenialReason.FORBIDDEN_NO_PERMISSION, asAlice.denialReason());
    }

    @Test
    @DisplayName("角色权限满足但范围不足：FORBIDDEN_INSUFFICIENT_SCOPE")
    void authenticatedButInsufficientScope() {
        // bob 是合法用户（认证与基础权限没问题），但令牌没有 reports:read 范围
        String header = bearerFor("bob");
        log.info("输入: user=bob(scopes=[openid]), 要求 scopes=[reports:read]");
        AccessDecision decision = accessControlService.decide(header, reportsArea);
        log.info("判定依据: 认证通过但 scopeOk=false -> reason={}, rationale={}",
                decision.denialReason(), decision.rationale());
        assertFalse(decision.allowed());
        assertEquals(AccessDenialReason.FORBIDDEN_INSUFFICIENT_SCOPE, decision.denialReason());
    }

    @Test
    @DisplayName("持有 reports:read 范围：放行")
    void scopeSatisfied() {
        String header = bearerFor("alice");
        log.info("输入: user=alice(scopes 含 reports:read), 要求 scopes=[reports:read]");
        AccessDecision decision = accessControlService.decide(header, reportsArea);
        log.info("判定: allowed={}, 依据={}", decision.allowed(), decision.rationale());
        assertTrue(decision.allowed());
    }

    @Test
    @DisplayName("仅要求认证时，任何有效令牌均放行")
    void anyAuthenticatedAllowed() {
        AccessDecision bob = accessControlService.decide(bearerFor("bob"), none);
        log.info("bob 访问仅认证入口: allowed={}", bob.allowed());
        assertTrue(bob.allowed());
        assertEquals("bob", bob.claims().username());
    }
}
