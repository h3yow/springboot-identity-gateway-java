package com.github.h3yow.springbootidentitygatewayjava.auth.token;

import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;

/**
 * 不透明令牌的 HMAC-SHA256 签名与校验工具。
 * 令牌格式：base64url(payload).base64url(hmac-sha256(payload))。
 */
@Component
public class TokenSigner {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final AuthProperties properties;

    public TokenSigner(AuthProperties properties) {
        this.properties = properties;
    }

    /** 对 payload 字节签名并组装成完整令牌字符串。 */
    public String sign(byte[] payload) {
        byte[] signature = hmac(secretKey(), payload);
        return urlEncoder().encodeToString(payload) + "." + urlEncoder().encodeToString(signature);
    }

    /**
     * 校验令牌签名并返回 payload 字节。
     *
     * @throws TokenException MALFORMED / BAD_SIGNATURE
     */
    public byte[] verify(String token) {
        if (token == null || token.isBlank()) {
            throw new TokenException(TokenRejectionReason.MALFORMED, "令牌为空");
        }
        int dot = token.indexOf('.');
        if (dot <= 0 || dot == token.length() - 1) {
            throw new TokenException(TokenRejectionReason.MALFORMED, "令牌格式不合法");
        }
        try {
            byte[] payload = urlDecoder().decode(token.substring(0, dot));
            byte[] signature = urlDecoder().decode(token.substring(dot + 1));
            byte[] expected = hmac(secretKey(), payload);
            if (!MessageDigest.isEqual(expected, signature)) {
                throw new TokenException(TokenRejectionReason.BAD_SIGNATURE, "令牌签名无效");
            }
            return payload;
        } catch (IllegalArgumentException ex) {
            throw new TokenException(TokenRejectionReason.MALFORMED, "令牌编码不合法");
        }
    }

    /** 计算令牌/验证码的 SHA-256 哈希（Hex），用于仅以哈希形式落库。 */
    public String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 不可用", ex);
        }
    }

    private byte[] secretKey() {
        String configured = properties.getTokenSigningKey();
        if (configured != null && !configured.isBlank()) {
            try {
                return urlDecoder().decode(configured);
            } catch (IllegalArgumentException ignored) {
                return configured.getBytes(StandardCharsets.UTF_8);
            }
        }
        return "local-dev-secret".getBytes(StandardCharsets.UTF_8);
    }

    static Base64.Encoder urlEncoder() {
        return Base64.getUrlEncoder().withoutPadding();
    }

    static Base64.Decoder urlDecoder() {
        return Base64.getUrlDecoder();
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception ex) {
            throw new IllegalStateException("HMAC 计算失败", ex);
        }
    }
}
