package com.github.h3yow.springbootidentitygatewayjava.auth.otp;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * 一次性验证码的签发与校验。
 * 服务端仅保存验证码的 SHA-256 哈希；校验结论可区分：
 * 无挑战 / 已过期 / 重复提交 / 验证码错误。
 */
@Service
public class OtpService {

    private static final Logger log = LoggerFactory.getLogger(OtpService.class);

    private final OtpStore store;
    private final Clock clock;
    private final AuthProperties properties;
    private final SecureRandom random = new SecureRandom();

    public OtpService(OtpStore store, Clock clock, AuthProperties properties) {
        this.store = store;
        this.clock = clock;
        this.properties = properties;
    }

    /** 为用户签发新挑战，旧挑战立即作废；返回明文验证码（仅本次返回）。 */
    public String issue(String username) {
        int number = random.nextInt(1_000_000);
        String code = String.format("%06d", number);
        long now = clock.nowMillis();
        OtpChallenge challenge = new OtpChallenge(
                username, sha256Hex(code), now + properties.getOtpTtlMillis(), false, now);
        store.save(challenge);
        log.info("OTP 签发: username={}, issuedAt={}, expiresAt={}, ttlMs={}",
                username, now, challenge.expiresAt(), properties.getOtpTtlMillis());
        return code;
    }

    /**
     * 原子校验：成功消费或得到可区分的失败结论。
     * 判定依据：挑战是否存在 -> 消费标记（重放）-> 到期时间 -> 码值。
     */
    public OtpVerificationResult verify(String username, String code) {
        long now = clock.nowMillis();
        OtpChallenge challenge = store.consume(username).orElse(null);
        if (challenge == null) {
            log.info("OTP 校验拒绝: username={}, input=<{}>, 依据=无未完成挑战", username, mask(code));
            return OtpVerificationResult.NO_CHALLENGE;
        }
        // consume 返回的是消费前的快照；若快照本身已被标记消费，说明是重复提交
        if (challenge.consumed()) {
            log.info("OTP 校验拒绝: username={}, input=<{}>, 依据=挑战已被消费(重复提交), issuedAt={}",
                    username, mask(code), challenge.issuedAt());
            return OtpVerificationResult.REUSED;
        }
        if (now > challenge.expiresAt()) {
            log.info("OTP 校验拒绝: username={}, input=<{}>, 依据=已过期, now={}, expiresAt={}",
                    username, mask(code), now, challenge.expiresAt());
            return OtpVerificationResult.EXPIRED;
        }
        if (!MessageDigest.isEqual(
                sha256Hex(code == null ? "" : code).getBytes(StandardCharsets.UTF_8),
                challenge.codeHash().getBytes(StandardCharsets.UTF_8))) {
            log.info("OTP 校验拒绝: username={}, input=<{}>, 依据=验证码不匹配, expiresAt={}",
                    username, mask(code), challenge.expiresAt());
            return OtpVerificationResult.MISMATCH;
        }
        log.info("OTP 校验通过: username={}, issuedAt={}, expiresAt={}", username, challenge.issuedAt(), challenge.expiresAt());
        return OtpVerificationResult.OK;
    }

    private static String mask(String code) {
        return code == null ? "null" : code;
    }

    static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 不可用", ex);
        }
    }
}
