package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginException;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginFailureReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionException;
import com.github.h3yow.springbootidentitygatewayjava.auth.session.SessionFailureReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenException;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.ApiError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * 将认证/令牌异常映射为可区分的 HTTP 响应：
 * <ul>
 *   <li>凭据/验证码类失败：401，reason 为具体失败原因枚举</li>
 *   <li>锁定：423 Locked，reason=ACCOUNT_LOCKED</li>
 *   <li>令牌失败：重放/撤销 401，过期 401，其余 400/401 按原因区分</li>
 *   <li>参数错误：400</li>
 * </ul>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final Map<LoginFailureReason, String> MESSAGES = Map.of(
            LoginFailureReason.BAD_CREDENTIALS, "用户名或密码错误",
            LoginFailureReason.ACCOUNT_LOCKED, "账户已被临时锁定",
            LoginFailureReason.OTP_EXPIRED, "动态验证码已过期",
            LoginFailureReason.OTP_REUSED, "动态验证码已被使用",
            LoginFailureReason.OTP_MISMATCH, "动态验证码错误",
            LoginFailureReason.OTP_MISSING, "缺少有效的动态验证码挑战");

    @ExceptionHandler(LoginException.class)
    public ResponseEntity<ApiError> handleLogin(LoginException ex) {
        HttpStatus status = ex.getReason() == LoginFailureReason.ACCOUNT_LOCKED
                ? HttpStatus.LOCKED : HttpStatus.UNAUTHORIZED;
        log.warn("登录失败响应: reason={}, status={}, message={}", ex.getReason(), status, ex.getMessage());
        return ResponseEntity.status(status).body(new ApiError(
                "login_failed", ex.getReason().name(), MESSAGES.getOrDefault(ex.getReason(), ex.getMessage())));
    }

    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ApiError> handleToken(TokenException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case MALFORMED, WRONG_TYPE -> HttpStatus.BAD_REQUEST;
            default -> HttpStatus.UNAUTHORIZED;
        };
        log.warn("令牌失败响应: reason={}, status={}, message={}", ex.getReason(), status, ex.getMessage());
        return ResponseEntity.status(status).body(new ApiError(
                "token_rejected", ex.getReason().name(), ex.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleBadRequest(IllegalArgumentException ex) {
        log.warn("请求参数错误: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiError("bad_request", "INVALID_ARGUMENT", ex.getMessage()));
    }

    /** 会话管理操作：他人会话 -> 403，会话不存在 -> 404，reason 可区分。 */
    @ExceptionHandler(SessionException.class)
    public ResponseEntity<ApiError> handleSession(SessionException ex) {
        HttpStatus status = ex.getReason() == SessionFailureReason.SESSION_NOT_OWNED
                ? HttpStatus.FORBIDDEN : HttpStatus.NOT_FOUND;
        log.warn("会话操作失败响应: reason={}, status={}, message={}", ex.getReason(), status, ex.getMessage());
        return ResponseEntity.status(status).body(new ApiError(
                "session_error", ex.getReason().name(), ex.getMessage()));
    }
}
