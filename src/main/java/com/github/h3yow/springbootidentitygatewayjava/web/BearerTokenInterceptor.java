package com.github.h3yow.springbootidentitygatewayjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.AccessControlService;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.AccessDecision;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.AccessDenialReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.access.RequireAccess;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.ApiError;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * 统一鉴权拦截器：对所有 /api 入口执行一致的默认拒绝判定。
 * <ul>
 *   <li>非 Controller 方法（静态资源等）直接放行</li>
 *   <li>未标注 {@link RequireAccess}：DEFAULT_DENY 403</li>
 *   <li>未认证：401；权限/范围不足：403，错误码可区分</li>
 * </ul>
 * 注意：/api/auth/** 中的登录端点同样受此约束，因此在 AuthController 上以
 * 方法级注解显式声明放行（PERMIT 要求为空且由该拦截器对公开端点豁免）。
 */
@Component
public class BearerTokenInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenInterceptor.class);

    private final AccessControlService accessControlService;
    private final ObjectMapper objectMapper;

    public BearerTokenInterceptor(AccessControlService accessControlService, ObjectMapper objectMapper) {
        this.accessControlService = accessControlService;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        // 显式标注为公开端点（登录、刷新、撤销）直接放行，由控制器自行校验输入
        if (handlerMethod.hasMethodAnnotation(PublicEndpoint.class)) {
            log.info("公开端点放行: {} {}", request.getMethod(), request.getRequestURI());
            return true;
        }

        RequireAccess requirement = handlerMethod.getMethodAnnotation(RequireAccess.class);
        if (requirement == null) {
            requirement = handlerMethod.getBeanType().getAnnotation(RequireAccess.class);
        }
        if (requirement == null) {
            log.info("默认拒绝: {} {} 未声明 @RequireAccess", request.getMethod(), request.getRequestURI());
            writeDenial(response, AccessDecision.deny(AccessDenialReason.DEFAULT_DENY,
                    "入口未声明访问要求，默认拒绝"));
            return false;
        }

        AccessDecision decision = accessControlService.decide(request.getHeader("Authorization"), requirement);
        if (!decision.allowed()) {
            log.info("访问被拒绝: {} {} reason={} rationale={}",
                    request.getMethod(), request.getRequestURI(),
                    decision.denialReason(), decision.rationale());
            writeDenial(response, decision);
            return false;
        }
        log.info("访问放行: {} {} user={} 依据={}", request.getMethod(), request.getRequestURI(),
                decision.claims().username(), decision.rationale());
        request.setAttribute("accessClaims", decision.claims());
        return true;
    }

    private void writeDenial(HttpServletResponse response, AccessDecision decision) throws Exception {
        HttpStatus status = statusFor(decision.denialReason());
        writeJson(response, status, new ApiError(
                "access_denied", decision.denialReason().name(), decision.rationale()));
    }

    private HttpStatus statusFor(AccessDenialReason reason) {
        return switch (reason) {
            case UNAUTHENTICATED -> HttpStatus.UNAUTHORIZED;
            case FORBIDDEN_NO_PERMISSION, FORBIDDEN_INSUFFICIENT_SCOPE, DEFAULT_DENY -> HttpStatus.FORBIDDEN;
        };
    }

    private void writeJson(HttpServletResponse response, HttpStatus status, ApiError error) throws Exception {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }
}
