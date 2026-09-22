package com.github.h3yow.springbootidentitygatewayjava.auth;

import com.github.h3yow.springbootidentitygatewayjava.error.ApiException;
import com.github.h3yow.springbootidentitygatewayjava.error.ErrorCode;
import com.github.h3yow.springbootidentitygatewayjava.model.AppUser;
import com.github.h3yow.springbootidentitygatewayjava.support.TimeProvider;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenPair;
import com.github.h3yow.springbootidentitygatewayjava.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.user.PasswordEncoder;
import com.github.h3yow.springbootidentitygatewayjava.user.UserStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 两步登录编排：
 * 第一步校验口令（失败计入锁定），通过后签发 OTP；
 * 第二步校验 OTP（不存在/过期/错误/重复可区分），通过后签发令牌对。
 */
@Service
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final UserStore userStore;
    private final PendingLoginStore pendingLoginStore;
    private final LoginFailureTracker failureTracker;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final TimeProvider timeProvider;

    public LoginService(UserStore userStore, PendingLoginStore pendingLoginStore,
                        LoginFailureTracker failureTracker, TokenService tokenService,
                        PasswordEncoder passwordEncoder, TimeProvider timeProvider) {
        this.userStore = userStore;
        this.pendingLoginStore = pendingLoginStore;
        this.failureTracker = failureTracker;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.timeProvider = timeProvider;
    }

    /** 第一步：校验口令与锁定状态，通过则创建待完成登录（内含一次性 OTP）。 */
    public PendingLogin startPasswordLogin(String username, String rawPassword) {
        if (username == null || username.isBlank() || rawPassword == null || rawPassword.isEmpty()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "用户名和密码不能为空");
        }
        if (failureTracker.isLocked(username)) {
            log.warn("第一步登录拒绝，账户锁定中: username={}", username);
            throw new ApiException(ErrorCode.LOGIN_ACCOUNT_LOCKED, "账户已临时锁定，请稍后再试");
        }
        AppUser user = userStore.find(username).orElse(null);
        boolean ok = user != null && passwordEncoder.matches(rawPassword, user.passwordHash());
        if (!ok) {
            java.time.Instant lockedUntil = failureTracker.recordFailure(username);
            log.warn("第一步登录拒绝，凭据错误: username={}, userExists={}, lockedUntil={}",
                    username, user != null, lockedUntil);
            if (lockedUntil != null) {
                throw new ApiException(ErrorCode.LOGIN_ACCOUNT_LOCKED,
                        "连续失败次数过多，账户已临时锁定至 " + lockedUntil);
            }
            throw new ApiException(ErrorCode.LOGIN_BAD_CREDENTIALS, "用户名或密码错误");
        }
        String otp = OtpGenerator.generate();
        PendingLogin pending = pendingLoginStore.create(
                username, otp, user.roles(), user.scopes());
        log.info("第一步登录通过，已签发一次性 OTP: username={}, pendingTokenTail={}, otp={}, expiresAt={}",
                username, tail(pending.pendingToken()), otp, pending.expiresAt());
        return pending;
    }

    /** 第二步：校验一次性验证码，通过则签发令牌对并重置失败计数。 */
    public TokenPair verifyOtpAndIssue(String pendingToken, String otpCode) {
        if (pendingToken == null || pendingToken.isBlank() || otpCode == null || otpCode.isBlank()) {
            throw new ApiException(ErrorCode.INVALID_REQUEST, "pendingToken 与 otp 不能为空");
        }
        PendingLogin pending = pendingLoginStore.find(pendingToken).orElse(null);
        if (pending == null) {
            log.warn("第二步登录拒绝，待完成登录不存在或已完成: pendingTokenTail={}", tail(pendingToken));
            throw new ApiException(ErrorCode.PENDING_LOGIN_NOT_FOUND, "登录会话不存在或已失效，请重新登录");
        }

        // 账户可能在第一步之后进入锁定；锁定优先于 OTP 判定。
        if (failureTracker.isLocked(pending.username())) {
            log.warn("第二步登录拒绝，账户锁定中: username={}", pending.username());
            throw new ApiException(ErrorCode.LOGIN_ACCOUNT_LOCKED, "账户已临时锁定，请稍后再试");
        }

        // 已过期先判定（过期与重复须可区分）。
        if (!timeProvider.now().isBefore(pending.expiresAt())) {
            log.warn("第二步登录拒绝，OTP 已过期: username={}, expiresAt={}, now={}",
                    pending.username(), pending.expiresAt(), timeProvider.now());
            throw new ApiException(ErrorCode.OTP_EXPIRED, "验证码已过期，请重新登录");
        }

        // 一次性：重复提交（含并发）只有第一个 markConsumed 成功，其余稳定得到 REPLAYED。
        if (!pending.markConsumed()) {
            log.warn("第二步登录拒绝，OTP 重复提交: username={}, pendingTokenTail={}",
                    pending.username(), tail(pendingToken));
            throw new ApiException(ErrorCode.OTP_REPLAYED, "验证码已被使用，请重新登录获取新验证码");
        }

        if (!otpCode.equals(pending.otpCode())) {
            // OTP 错误也计入连续失败，累积到阈值同样触发锁定。
            failureTracker.recordFailure(pending.username());
            log.warn("第二步登录拒绝，OTP 错误: username={}, submitted={}, expected={}",
                    pending.username(), otpCode, pending.otpCode());
            throw new ApiException(ErrorCode.OTP_INVALID, "验证码错误");
        }

        failureTracker.reset(pending.username());
        TokenPair pair = tokenService.issue(pending.username(), pending.roles(), pending.scopes());
        log.info("两步登录完成，令牌已签发: username={}, sessionId={}",
                pending.username(), pair.sessionId());
        return pair;
    }

    private static String tail(String token) {
        if (token == null || token.length() < 6) {
            return "***";
        }
        return "…" + token.substring(token.length() - 6);
    }
}
