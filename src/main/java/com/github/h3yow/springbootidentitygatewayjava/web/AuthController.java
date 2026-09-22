package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.auth.LoginService;
import com.github.h3yow.springbootidentitygatewayjava.auth.PendingLogin;
import com.github.h3yow.springbootidentitygatewayjava.security.Authentication;
import com.github.h3yow.springbootidentitygatewayjava.security.AuthInterceptor;
import com.github.h3yow.springbootidentitygatewayjava.security.RequireScope;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenPair;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.LoginStartRequest;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.LoginStartResponse;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.MessageResponse;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.OtpVerifyRequest;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.RefreshRequest;
import com.github.h3yow.springbootidentitygatewayjava.web.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 认证相关端点：两步登录、令牌轮换公开；登出需携带有效访问令牌。 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final LoginService loginService;
    private final TokenService tokenService;

    public AuthController(LoginService loginService, TokenService tokenService) {
        this.loginService = loginService;
        this.tokenService = tokenService;
    }

    /** 第一步：用户名 + 密码，通过后返回 pendingToken 与 OTP 提示（本地演示直接回显 OTP）。 */
    @PostMapping("/login/password")
    public LoginStartResponse startLogin(@RequestBody LoginStartRequest request) {
        PendingLogin pending = loginService.startPasswordLogin(request.username(), request.password());
        return new LoginStartResponse(pending.pendingToken(), pending.otpCode(), pending.expiresAt());
    }

    /** 第二步：pendingToken + 一次性 OTP，通过后签发令牌对。 */
    @PostMapping("/login/otp")
    public TokenResponse verifyOtp(@RequestBody OtpVerifyRequest request) {
        TokenPair pair = loginService.verifyOtpAndIssue(request.pendingToken(), request.otp());
        return TokenResponse.from(pair);
    }

    /** 使用一次性刷新令牌轮换；重放（含并发）仅一次成功，其余吊销整族。 */
    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody RefreshRequest request) {
        return TokenResponse.from(tokenService.refresh(request.refreshToken()));
    }

    /** 登出：撤销当前会话，其下全部访问/刷新令牌立即失效。 */
    @PostMapping("/logout")
    @RequireScope
    public MessageResponse logout(HttpServletRequest request) {
        Authentication auth = (Authentication) request.getAttribute(AuthInterceptor.AUTH_ATTRIBUTE);
        tokenService.revokeSession(auth.sessionId());
        return new MessageResponse("会话已注销，全部令牌失效");
    }
}
