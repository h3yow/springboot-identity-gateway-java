package com.github.h3yow.springbootidentitygatewayjava.auth.login;

import com.github.h3yow.springbootidentitygatewayjava.auth.credential.PasswordHasher;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserAccount;
import com.github.h3yow.springbootidentitygatewayjava.auth.domain.UserDirectory;
import com.github.h3yow.springbootidentitygatewayjava.auth.otp.OtpService;
import com.github.h3yow.springbootidentitygatewayjava.auth.otp.OtpVerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 两步登录编排：第一步校验密码并签发 OTP，第二步校验 OTP 完成登录。
 * 失败原因可区分：BAD_CREDENTIALS / ACCOUNT_LOCKED / OTP_MISSING / OTP_EXPIRED /
 * OTP_REUSED / OTP_MISMATCH。
 */
@Service
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final UserDirectory users;
    private final PasswordHasher passwordHasher;
    private final OtpService otpService;
    private final LoginFailureCounter failureCounter;

    public LoginService(UserDirectory users, PasswordHasher passwordHasher,
                        OtpService otpService, LoginFailureCounter failureCounter) {
        this.users = users;
        this.passwordHasher = passwordHasher;
        this.otpService = otpService;
        this.failureCounter = failureCounter;
    }

    /**
     * 第一步：校验密码。成功签发 OTP；密码错误记录失败并可能锁定。
     *
     * @return 明文 OTP（仅在本地开发模式下由上层回显）
     */
    public String verifyPassword(String username, String password) {
        log.info("登录第一步(密码): username={}", username);
        if (failureCounter.isLocked(username)) {
            throw new LoginException(LoginFailureReason.ACCOUNT_LOCKED,
                    "账户已被临时锁定，请稍后再试: " + username);
        }
        UserAccount account = users.findByUsername(username).orElse(null);
        if (account == null || !passwordHasher.matches(password, account.passwordHash())) {
            boolean locked = failureCounter.recordFailure(username);
            LoginFailureReason reason = locked
                    ? LoginFailureReason.ACCOUNT_LOCKED
                    : LoginFailureReason.BAD_CREDENTIALS;
            log.warn("密码校验失败: username={}, 结论={}, failures={}",
                    username, reason, failureCounter.currentFailures(username));
            throw new LoginException(reason,
                    locked ? "失败次数过多，账户已被临时锁定: " + username : "用户名或密码错误");
        }
        String otp = otpService.issue(username);
        log.info("密码校验通过并已签发 OTP: username={}", username);
        return otp;
    }

    /** 第二步：校验 OTP；成功返回用户名（上层据此签发令牌）。 */
    public String verifyOtp(String username, String otp) {
        log.info("登录第二步(OTP): username={}", username);
        if (failureCounter.isLocked(username)) {
            throw new LoginException(LoginFailureReason.ACCOUNT_LOCKED,
                    "账户已被临时锁定，请稍后再试: " + username);
        }
        if (otp == null || otp.isBlank()) {
            failureCounter.recordFailure(username);
            throw new LoginException(LoginFailureReason.OTP_MISSING, "缺少动态验证码");
        }
        OtpVerificationResult result = otpService.verify(username, otp);
        switch (result) {
            case OK -> {
                failureCounter.reset(username);
                log.info("两步登录成功: username={}", username);
                return username;
            }
            case NO_CHALLENGE -> {
                failureCounter.recordFailure(username);
                throw new LoginException(LoginFailureReason.OTP_MISSING,
                        "未找到验证码挑战，请先完成密码校验");
            }
            case EXPIRED -> {
                failureCounter.recordFailure(username);
                throw new LoginException(LoginFailureReason.OTP_EXPIRED, "动态验证码已过期，请重新登录");
            }
            case REUSED -> {
                failureCounter.recordFailure(username);
                throw new LoginException(LoginFailureReason.OTP_REUSED, "动态验证码已被使用，请勿重复提交");
            }
            case MISMATCH -> {
                failureCounter.recordFailure(username);
                throw new LoginException(LoginFailureReason.OTP_MISMATCH, "动态验证码错误");
            }
            default -> throw new LoginException(LoginFailureReason.OTP_MISMATCH, "动态验证码校验失败");
        }
    }
}
