package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.springbootidentitygatewayjava.auth.login.LoginFailureCounter;
import com.github.h3yow.springbootidentitygatewayjava.auth.otp.OtpStore;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenStore;
import com.github.h3yow.springbootidentitygatewayjava.config.AuthProperties;
import com.github.h3yow.springbootidentitygatewayjava.tests.support.MutableClock;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端 HTTP 闭环测试：两步登录 -> 持令牌访问 -> 刷新轮换 -> 重放撤销 -> 权限边界 -> 锁定。
 * 使用固定起步时间的可控时钟，过期/锁定结论可稳定复现；不依赖网络与外部服务。
 */
@SpringBootTest(properties = {
        "auth.max-failures=3",
        "auth.lock-millis=60000",
        "auth.otp-ttl-millis=30000",
        "auth.access-token-ttl-millis=900000",
        "auth.refresh-token-ttl-millis=600000",
        "auth.expose-otp-for-local-dev=true"
})
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowIntegrationTest.class);
    private static final long T0 = 1_700_000_000_000L;

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        Clock fixedClock(AuthProperties properties) {
            return new MutableClock(T0);
        }
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private Clock clock;
    @Autowired
    private OtpStore otpStore;
    @Autowired
    private LoginFailureCounter failureCounter;
    @Autowired
    private TokenStore tokenStore;

    @BeforeEach
    void resetState() {
        // Spring 上下文跨用例共享，每个用例前重置时钟与全部有状态存储，保证相互隔离、结论稳定
        mutableClock().setNow(T0);
        otpStore.clear();
        failureCounter.clear();
        tokenStore.clear();
    }

    private MutableClock mutableClock() {
        return (MutableClock) clock;
    }

    private String json(String... keyValues) throws Exception {
        var node = objectMapper.createObjectNode();
        for (int i = 0; i < keyValues.length; i += 2) {
            node.put(keyValues[i], keyValues[i + 1]);
        }
        return objectMapper.writeValueAsString(node);
    }

    /** 完成两步登录，返回令牌响应 JSON。 */
    private JsonNode login(String username, String password) throws Exception {
        MvcResult step1 = mockMvc.perform(post("/api/auth/login/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", username, "password", password)))
                .andExpect(status().isOk())
                .andReturn();
        String otp = objectMapper.readTree(step1.getResponse().getContentAsString()).get("otpForLocalDev").asText();
        log.info("集成登录: user={} 获取 OTP=<{}>", username, otp);

        MvcResult step2 = mockMvc.perform(post("/api/auth/login/otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", username, "otp", otp)))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(step2.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("完整闭环：两步登录后访问profile成功，三类拒绝可区分")
    void fullFlowWithDistinctDenials() throws Exception {
        JsonNode tokens = login("bob", "password-bob");
        String accessToken = tokens.get("accessToken").asText();
        log.info("登录成功取得令牌");

        // 1) 未认证 -> 401 UNAUTHENTICATED
        log.info("场景1: 不带令牌访问 /api/protected/profile");
        mockMvc.perform(get("/api/protected/profile"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));

        // 2) 已认证访问 profile -> 200
        log.info("场景2: bob 带令牌访问 profile");
        mockMvc.perform(get("/api/protected/profile").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("bob"));

        // 3) 已认证但无权限 -> 403 FORBIDDEN_NO_PERMISSION
        log.info("场景3: bob 访问 /api/protected/admin（无admin角色/user:write权限）");
        mockMvc.perform(get("/api/protected/admin").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("FORBIDDEN_NO_PERMISSION"));

        // 4) 范围不足 -> 403 FORBIDDEN_INSUFFICIENT_SCOPE（与无权限区分）
        log.info("场景4: bob 访问 /api/protected/reports（缺 reports:read 范围）");
        mockMvc.perform(get("/api/protected/reports").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("FORBIDDEN_INSUFFICIENT_SCOPE"));

        // 5) alice 持有 reports:read -> 200
        JsonNode aliceTokens = login("alice", "password-alice");
        log.info("场景5: alice 访问 reports（持有 reports:read）");
        mockMvc.perform(get("/api/protected/reports")
                        .header("Authorization", "Bearer " + aliceTokens.get("accessToken").asText()))
                .andExpect(status().isOk());

        // 6) 未标注入口默认拒绝 -> 403 DEFAULT_DENY
        log.info("场景6: 访问未标注 @RequireAccess 的 /api/protected/unannotated");
        mockMvc.perform(get("/api/protected/unannotated").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("DEFAULT_DENY"));
    }

    @Test
    @DisplayName("HTTP 层刷新轮换与重放：重放后新令牌也失效")
    void httpRotationAndReplay() throws Exception {
        JsonNode first = login("alice", "password-alice");
        String oldRefresh = first.get("refreshToken").asText();

        MvcResult rotated = mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("refreshToken", oldRefresh)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode second = objectMapper.readTree(rotated.getResponse().getContentAsString());
        log.info("HTTP 轮换成功");

        // 重放旧刷新令牌 -> 401 ROTATED，整族撤销
        log.info("HTTP 重放旧刷新令牌");
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("refreshToken", oldRefresh)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("ROTATED"));

        // 轮换得到的新访问令牌立即失效
        log.info("重放后使用新访问令牌访问 profile");
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + second.get("accessToken").asText()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("HTTP 层访问令牌过期：推进可控时钟后得到401")
    void httpAccessTokenExpiry() throws Exception {
        JsonNode tokens = login("alice", "password-alice");
        String accessToken = tokens.get("accessToken").asText();
        log.info("推进时钟 900001ms 超过访问令牌有效期");
        mutableClock().advance(900_001L);
        mockMvc.perform(get("/api/protected/profile").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("HTTP 层连续失败锁定与窗口到期恢复")
    void httpLockoutAndRecovery() throws Exception {
        for (int i = 1; i <= 3; i++) {
            log.info("第{}次错误密码", i);
            int expectedStatus = i < 3 ? 401 : 423;
            String expectedReason = i < 3 ? "BAD_CREDENTIALS" : "ACCOUNT_LOCKED";
            mockMvc.perform(post("/api/auth/login/password")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json("username", "alice", "password", "wrong")))
                    .andExpect(status().is(expectedStatus))
                    .andExpect(jsonPath("$.reason").value(expectedReason));
        }
        // 锁定期间正确密码同样 423
        mockMvc.perform(post("/api/auth/login/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", "alice", "password", "password-alice")))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.reason").value("ACCOUNT_LOCKED"));

        // 窗口到期自动恢复
        log.info("推进时钟 60001ms，锁定窗口到期");
        mutableClock().advance(60_001L);
        JsonNode tokens = login("alice", "password-alice");
        log.info("窗口到期后重新登录成功");
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + tokens.get("accessToken").asText()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("HTTP 层 OTP 过期与重复提交返回可区分原因")
    void httpOtpExpiryAndReplay() throws Exception {
        MvcResult step1 = mockMvc.perform(post("/api/auth/login/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", "alice", "password", "password-alice")))
                .andExpect(status().isOk())
                .andReturn();
        String otp = objectMapper.readTree(step1.getResponse().getContentAsString()).get("otpForLocalDev").asText();

        log.info("推进时钟超过 OTP 有效期 30001ms");
        mutableClock().advance(30_001L);
        mockMvc.perform(post("/api/auth/login/otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", "alice", "otp", otp)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("OTP_EXPIRED"));
    }
}
