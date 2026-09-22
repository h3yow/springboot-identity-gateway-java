package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.security.Authentication;
import com.github.h3yow.springbootidentitygatewayjava.security.AuthInterceptor;
import com.github.h3yow.springbootidentitygatewayjava.security.RequireScope;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** 用于演示与验证访问控制边界的受保护资源。 */
@RestController
@RequestMapping("/api/resources")
public class ProtectedController {

    /** 仅需登录，任何已认证主体可访问。 */
    @GetMapping("/profile")
    @RequireScope
    public Map<String, Object> profile(HttpServletRequest request) {
        Authentication auth = (Authentication) request.getAttribute(AuthInterceptor.AUTH_ATTRIBUTE);
        return body(auth, "profile");
    }

    /** 需要 orders:read 权限范围。 */
    @GetMapping("/orders")
    @RequireScope("orders:read")
    public Map<String, Object> orders(HttpServletRequest request) {
        Authentication auth = (Authentication) request.getAttribute(AuthInterceptor.AUTH_ATTRIBUTE);
        return body(auth, "orders");
    }

    /** 需要 admin 角色且具备 admin:write 范围。 */
    @GetMapping("/admin")
    @RequireScope(value = "admin:write", roles = "admin")
    public Map<String, Object> admin(HttpServletRequest request) {
        Authentication auth = (Authentication) request.getAttribute(AuthInterceptor.AUTH_ATTRIBUTE);
        return body(auth, "admin");
    }

    static Map<String, Object> body(Authentication auth, String resource) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("resource", resource);
        map.put("username", auth.username());
        map.put("sessionId", auth.sessionId());
        map.put("roles", auth.roles());
        map.put("scopes", auth.scopes());
        return map;
    }
}
