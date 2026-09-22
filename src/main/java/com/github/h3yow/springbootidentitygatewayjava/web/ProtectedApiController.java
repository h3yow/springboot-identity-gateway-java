package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.auth.access.RequireAccess;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.AccessTokenClaims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 受保护演示入口，用于区分三类访问控制结论与默认拒绝。
 */
@RestController
@RequestMapping("/api/protected")
public class ProtectedApiController {

    /** 任意已认证用户可访问。 */
    @GetMapping("/profile")
    @RequireAccess
    public Map<String, Object> profile(HttpServletRequest request) {
        return claimsView(currentClaims(request));
    }

    /** 需要 admin 角色或 user:write 权限。 */
    @GetMapping("/admin")
    @RequireAccess(roles = {"admin"}, permissions = {"user:write"})
    public Map<String, Object> admin(HttpServletRequest request) {
        return claimsView(currentClaims(request));
    }

    /** 需要 access 令牌携带 reports:read 范围。 */
    @GetMapping("/reports")
    @RequireAccess(scopes = {"reports:read"})
    public Map<String, Object> reports(HttpServletRequest request) {
        return claimsView(currentClaims(request));
    }

    /** 未标注，默认拒绝。 */
    @GetMapping("/unannotated")
    public Map<String, Object> unannotated() {
        return Map.of();
    }

    private AccessTokenClaims currentClaims(HttpServletRequest request) {
        return (AccessTokenClaims) request.getAttribute("accessClaims");
    }

    private Map<String, Object> claimsView(AccessTokenClaims claims) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("username", claims.username());
        view.put("roles", claims.roles());
        view.put("permissions", claims.permissions());
        view.put("scopes", claims.scopes());
        view.put("expiresAt", claims.expiresAt());
        return view;
    }
}
