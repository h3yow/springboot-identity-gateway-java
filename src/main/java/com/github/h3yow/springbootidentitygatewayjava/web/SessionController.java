package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.auth.access.RequireAccess;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionService;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.AccessTokenClaims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 多端会话管理入口：会话清单与按会话精准下线。
 * 均标注 {@link RequireAccess}，必须携带有效访问令牌，属主身份取自令牌 claims，
 * 因此清单与撤销都严格限定为“自己的会话”，无法通过传入他人会话 id 越权。
 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    /** 查看当前用户的有效会话清单（仅自己、仅有效）。 */
    @GetMapping
    @RequireAccess
    public Map<String, Object> list(HttpServletRequest request) {
        AccessTokenClaims claims = currentClaims(request);
        List<SessionInfo> sessions = sessionService.listSessions(claims.username());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", claims.username());
        body.put("count", sessions.size());
        body.put("sessions", sessions);
        return body;
    }

    /**
     * 按会话 id 精准下线。重复撤销结论一致：始终返回 REVOKED，
     * {@code changed=false} 表示该会话此前已处于终态。
     */
    @PostMapping("/{sessionId}/revoke")
    @RequireAccess
    public Map<String, Object> revoke(@PathVariable String sessionId, HttpServletRequest request) {
        AccessTokenClaims claims = currentClaims(request);
        boolean changed = sessionService.revokeSession(claims.username(), sessionId);
        return Map.of("status", "REVOKED", "sessionId", sessionId, "changed", changed);
    }

    private AccessTokenClaims currentClaims(HttpServletRequest request) {
        return (AccessTokenClaims) request.getAttribute("accessClaims");
    }
}
