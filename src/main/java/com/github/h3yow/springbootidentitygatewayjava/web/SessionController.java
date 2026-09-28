package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.auth.access.RequireAccess;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionInfo;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionService;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionState;
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
 * 多端会话管理入口：查看本人有效会话清单、按会话精准下线。
 * 均为需登录的受保护端点（至少要认证）；属主隔离由 {@link SessionService} 保证。
 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private final SessionService sessionService;

    public SessionController(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    /** 列出本人当前有效会话；只能看到自己的，已撤销/淘汰/过期的不出现。 */
    @GetMapping
    @RequireAccess
    public List<SessionInfo> list(HttpServletRequest request) {
        AccessTokenClaims claims = currentClaims(request);
        return sessionService.listActiveSessions(claims.username());
    }

    /** 精准撤销（下线）本人的指定会话；对同一会话重复撤销结论一致。 */
    @PostMapping("/{sessionId}/revoke")
    @RequireAccess
    public Map<String, Object> revoke(@PathVariable String sessionId, HttpServletRequest request) {
        AccessTokenClaims claims = currentClaims(request);
        SessionState state = sessionService.revokeSession(claims.username(), sessionId);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "REVOKED");
        body.put("sessionId", sessionId);
        body.put("state", state.name());
        return body;
    }

    private AccessTokenClaims currentClaims(HttpServletRequest request) {
        return (AccessTokenClaims) request.getAttribute("accessClaims");
    }
}
