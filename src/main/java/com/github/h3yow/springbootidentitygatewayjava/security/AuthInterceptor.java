package com.github.h3yow.springbootidentitygatewayjava.security;

import com.github.h3yow.springbootidentitygatewayjava.error.ApiException;
import com.github.h3yow.springbootidentitygatewayjava.error.ErrorCode;
import com.github.h3yow.springbootidentitygatewayjava.token.SessionStore;
import com.github.h3yow.springbootidentitygatewayjava.token.StoredAccessToken;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.List;

/**
 * 统一鉴权拦截器，保证各受保护入口判定一致、默认拒绝：
 * 1. 无/坏/过期/撤销令牌 -> TOKEN_*（未认证，401）；
 * 2. 角色不满足 -> ACCESS_DENIED_ROLE（403）；
 * 3. 范围不覆盖目标 -> ACCESS_DENIED_SCOPE（403）。
 * 判定依据（所需角色/范围、主体角色/范围）随日志打印，便于解释结论。
 * 非 HandlerMethod 默认拒绝，避免意外放行。
 */
@Component
public class AuthInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthInterceptor.class);
    private static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTH_ATTRIBUTE = Authentication.class.getName();

    private final TokenService tokenService;
    private final SessionStore sessionStore;

    public AuthInterceptor(TokenService tokenService, SessionStore sessionStore) {
        this.tokenService = tokenService;
        this.sessionStore = sessionStore;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            // 默认拒绝：非控制器方法（静态资源/未知映射）不放行。
            log.warn("默认拒绝非处理器请求: path={}, handler={}", request.getRequestURI(), handler);
            throw new ApiException(ErrorCode.ACCESS_DENIED_ROLE, "默认拒绝：非受保护处理器");
        }
        RequireScope required = handlerMethod.getMethodAnnotation(RequireScope.class);
        if (required == null) {
            // 默认拒绝：未显式声明权限要求的控制器方法不放行。
            log.warn("默认拒绝未标注 @RequireScope 的入口: path={}, method={}",
                    request.getRequestURI(), handlerMethod.getMethod().getName());
            throw new ApiException(ErrorCode.ACCESS_DENIED_ROLE, "默认拒绝：入口未声明访问要求");
        }

        String token = extractBearer(request);
        // verifyAccessToken 对缺失/畸形/过期/撤销分别抛出可区分错误码（401 家族）。
        StoredAccessToken stored = tokenService.verifyAccessToken(token);
        TokenSession session = sessionStore.findById(stored.sessionId())
                .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_REVOKED, "会话不存在"));

        List<String> needRoles = Arrays.asList(required.roles());
        List<String> needScopes = Arrays.asList(required.value());

        if (!needRoles.isEmpty() && session.roles().stream().noneMatch(needRoles::contains)) {
            log.warn("访问拒绝(角色不足): path={}, username={}, requiredRoles={}, subjectRoles={}",
                    request.getRequestURI(), session.username(), needRoles, session.roles());
            throw new ApiException(ErrorCode.ACCESS_DENIED_ROLE,
                    "角色不足：需要 " + needRoles + "，实际 " + session.roles());
        }
        if (!needScopes.isEmpty() && session.scopes().stream().noneMatch(needScopes::contains)) {
            log.warn("访问拒绝(范围不足): path={}, username={}, requiredScopes={}, subjectScopes={}",
                    request.getRequestURI(), session.username(), needScopes, session.scopes());
            throw new ApiException(ErrorCode.ACCESS_DENIED_SCOPE,
                    "权限范围不足：需要 " + needScopes + "，实际 " + session.scopes());
        }

        Authentication authentication = new Authentication(
                session.username(), session.sessionId(), session.roles(), session.scopes());
        request.setAttribute(AUTH_ATTRIBUTE, authentication);
        log.info("访问允许: path={}, username={}, requiredRoles={}, requiredScopes={}, subjectRoles={}, subjectScopes={}",
                request.getRequestURI(), session.username(), needRoles, needScopes,
                session.roles(), session.scopes());
        return true;
    }

    private String extractBearer(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            log.warn("访问拒绝(未认证)：缺少 Bearer 令牌, path={}", request.getRequestURI());
            throw new ApiException(ErrorCode.TOKEN_MISSING, "缺少 Authorization: Bearer 令牌");
        }
        return header.substring(BEARER_PREFIX.length()).trim();
    }
}
