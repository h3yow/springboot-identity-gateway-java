package com.github.h3yow.springbootidentitygatewayjava.web;

import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginClientContext;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginException;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginFailureReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginService;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.IssuedTokens;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 认证入口：两步登录、刷新、撤销。均为公开端点（自带凭据/令牌校验）。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final LoginService loginService;
    private final TokenService tokenService;
    private final UserDirectory userDirectory;
    private final AuthProperties properties;

    public AuthController(LoginService loginService, TokenService tokenService,
                          UserDirectory userDirectory, AuthProperties properties) {
        this.loginService = loginService;
        this.tokenService = tokenService;
        this.userDirectory = userDirectory;
        this.properties = properties;
    }

    /** 第一步：密码换 OTP 挑战。 */
    @PublicEndpoint
    @PostMapping("/login/password")
    public ResponseEntity<?> passwordStep(@RequestBody Map<String, String> body) {
        String username = required(body, "username");
        String password = required(body, "password");
        String otp = loginService.verifyPassword(username, password);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "OTP_REQUIRED");
        response.put("username", username);
        if (properties.isExposeOtpForLocalDev()) {
            // 本地开发辅助：无短信/邮件渠道时直接回显，生产环境必须关闭
            response.put("otpForLocalDev", otp);
        }
        log.info("第一步成功: username={}, 本地回显OTP={}", username, properties.isExposeOtpForLocalDev());
        return ResponseEntity.ok(response);
    }

    /** 第二步：OTP 换令牌。可携带 deviceId/deviceName/clientId 以区分多端会话。 */
    @PublicEndpoint
    @PostMapping("/login/otp")
    public IssuedTokens otpStep(@RequestBody Map<String, String> body) {
        String username = required(body, "username");
        String otp = required(body, "otp");
        String authenticated = loginService.verifyOtp(username, otp);
        UserAccount account = requireAccount(authenticated);
        LoginClientContext client = new LoginClientContext(
                optional(body, "deviceId"), optional(body, "deviceName"), optional(body, "clientId"));
        IssuedTokens tokens = tokenService.issueFor(account, client);
        log.info("第二步成功，已签发令牌: username={}, sessionId={}, device={}, client={}",
                authenticated, tokens.sessionId(), client.deviceId(), client.clientId());
        return tokens;
    }

    /** 刷新令牌一次性轮换。 */
    @PublicEndpoint
    @PostMapping("/token/refresh")
    public IssuedTokens refresh(@RequestBody Map<String, String> body) {
        String refreshToken = required(body, "refreshToken");
        log.info("收到刷新请求");
        return tokenService.rotate(refreshToken);
    }

    /** 撤销当前刷新令牌所属会话。 */
    @PublicEndpoint
    @PostMapping("/token/revoke")
    public Map<String, Object> revoke(@RequestBody Map<String, String> body) {
        String refreshToken = required(body, "refreshToken");
        tokenService.revoke(refreshToken);
        log.info("撤销请求完成");
        return Map.of("status", "REVOKED");
    }

    private UserAccount requireAccount(String username) {
        return userDirectory.findByUsername(username)
                .orElseThrow(() -> new LoginException(LoginFailureReason.BAD_CREDENTIALS, "用户不存在: " + username));
    }

    private static String required(Map<String, String> body, String key) {
        String value = body == null ? null : body.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("缺少必填参数: " + key);
        }
        return value;
    }

    private static String optional(Map<String, String> body, String key) {
        String value = body == null ? null : body.get(key);
        return value == null || value.isBlank() ? null : value;
    }
}
