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
 * 多端会话管理 HTTP 端到端测试：登录携带设备信息 -> 清单 -> 精准下线 -> 容量淘汰 -> 拒绝结论。
 * 时钟可控、状态每用例重置，离线可重复。
 */
@SpringBootTest(properties = {
        "auth.max-failures=5",
        "auth.lock-millis=60000",
        "auth.otp-ttl-millis=300000",
        "auth.access-token-ttl-millis=900000",
        "auth.refresh-token-ttl-millis=600000",
        "auth.max-sessions-per-user=2",
        "auth.expose-otp-for-local-dev=true"
})
@AutoConfigureMockMvc
class SessionHttpIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(SessionHttpIntegrationTest.class);
    private static final long T0 = 1_700_000_000_000L;

    @TestConfiguration
    static class FixedClockConfig {
        @Bean
        @Primary
        Clock fixedClock() {
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
        mutableClock().setNow(T0);
        otpStore.clear();
        failureCounter.clear();
        tokenStore.clear();
    }

    private MutableClock mutableClock() {
        return (MutableClock) clock;
    }

    private String json(String... kv) throws Exception {
        var node = objectMapper.createObjectNode();
        for (int i = 0; i < kv.length; i += 2) {
            node.put(kv[i], kv[i + 1]);
        }
        return objectMapper.writeValueAsString(node);
    }

    /** 两步登录并携带设备/客户端信息，返回令牌响应。 */
    private JsonNode login(String username, String password, String deviceId, String clientId) throws Exception {
        MvcResult step1 = mockMvc.perform(post("/api/auth/login/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", username, "password", password)))
                .andExpect(status().isOk()).andReturn();
        String otp = objectMapper.readTree(step1.getResponse().getContentAsString()).get("otpForLocalDev").asText();
        MvcResult step2 = mockMvc.perform(post("/api/auth/login/otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("username", username, "otp", otp,
                                "deviceId", deviceId, "deviceName", deviceId + "-name", "clientId", clientId)))
                .andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(step2.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("清单：多端登录后 GET /api/sessions 仅返回本人有效会话并区分设备、含能力概要")
    void listSessionsShowsOwnDevicesAndCapabilities() throws Exception {
        JsonNode phone = login("alice", "password-alice", "phone-1", "mobile");
        mockMvc.perform(get("/api/sessions").header("Authorization", "Bearer " + phone.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.count").value(1))
                .andExpect(jsonPath("$.sessions[0].deviceId").value("phone-1"))
                .andExpect(jsonPath("$.sessions[0].clientId").value("mobile"))
                .andExpect(jsonPath("$.sessions[0].roles[0]").value("user"))
                .andExpect(jsonPath("$.sessions[0].scopes[?(@=='reports:read')]").exists());

        JsonNode laptop = login("alice", "password-alice", "laptop-9", "web");
        mockMvc.perform(get("/api/sessions").header("Authorization", "Bearer " + laptop.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(2));
        log.info("HTTP 清单正确返回两个不同设备会话");
    }

    @Test
    @DisplayName("清单需要认证：无令牌 401；他人无法通过清单看到别人会话")
    void listSessionsRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/sessions"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
        JsonNode bob = login("bob", "password-bob", "bob-phone", "mobile");
        mockMvc.perform(get("/api/sessions").header("Authorization", "Bearer " + bob.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(1))
                .andExpect(jsonPath("$.sessions[0].deviceId").value("bob-phone"));
    }

    @Test
    @DisplayName("按会话下线：撤销目标会话后其令牌 401，其它设备照常；重复撤销返回 REVOKED")
    void revokeSpecificSessionEndToEnd() throws Exception {
        JsonNode phone = login("alice", "password-alice", "phone-1", "mobile");
        JsonNode laptop = login("alice", "password-alice", "laptop-9", "web");
        String phoneSession = phone.get("sessionId").asText();

        // 首次撤销 changed=true
        mockMvc.perform(post("/api/sessions/" + phoneSession + "/revoke")
                        .header("Authorization", "Bearer " + phone.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"))
                .andExpect(jsonPath("$.changed").value(true));

        // 被撤销手机：访问 -> 401
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + phone.get("accessToken").asText()))
                .andExpect(status().isUnauthorized());
        // 被撤销手机：续期 -> 401 REVOKED
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("refreshToken", phone.get("refreshToken").asText())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("REVOKED"));

        // 笔记本照常
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + laptop.get("accessToken").asText()))
                .andExpect(status().isOk());

        // 清单只剩笔记本
        mockMvc.perform(get("/api/sessions").header("Authorization", "Bearer " + laptop.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(1))
                .andExpect(jsonPath("$.sessions[0].deviceId").value("laptop-9"));

        // 重复撤销：仍 200 REVOKED，但 changed=false
        mockMvc.perform(post("/api/sessions/" + phoneSession + "/revoke")
                        .header("Authorization", "Bearer " + laptop.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"))
                .andExpect(jsonPath("$.changed").value(false));
    }

    @Test
    @DisplayName("撤销他人会话：404 SESSION_NOT_FOUND，不影响该会话")
    void revokeOthersSessionReturns404() throws Exception {
        JsonNode alice = login("alice", "password-alice", "alice-phone", "mobile");
        JsonNode bob = login("bob", "password-bob", "bob-phone", "mobile");
        String aliceSession = alice.get("sessionId").asText();

        mockMvc.perform(post("/api/sessions/" + aliceSession + "/revoke")
                        .header("Authorization", "Bearer " + bob.get("accessToken").asText()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_FOUND"));

        // alice 会话仍可用
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + alice.get("accessToken").asText()))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("容量淘汰：上限 2，第三次登录挤掉最久未活跃会话，被挤设备后续访问得到 401 EVICTED")
    void evictionOverHttpReturnsDistinctEvictedReason() throws Exception {
        JsonNode s1 = login("alice", "password-alice", "dev-1", "c");
        mutableClock().advance(1_000L);
        JsonNode s2 = login("alice", "password-alice", "dev-2", "c");
        // 让 dev-2 活跃，dev-1 成为最久未活跃
        mutableClock().advance(10_000L);
        mockMvc.perform(get("/api/protected/profile")
                .header("Authorization", "Bearer " + s2.get("accessToken").asText())).andExpect(status().isOk());
        JsonNode s3 = login("alice", "password-alice", "dev-3", "c");

        // dev-1 被淘汰：访问 401 且令牌层 reason=EVICTED（通过刷新端点观察拒绝原因）
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("refreshToken", s1.get("refreshToken").asText())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("EVICTED"));

        // dev-2、dev-3 仍正常
        mockMvc.perform(get("/api/protected/profile")
                .header("Authorization", "Bearer " + s2.get("accessToken").asText())).andExpect(status().isOk());
        mockMvc.perform(get("/api/protected/profile")
                .header("Authorization", "Bearer " + s3.get("accessToken").asText())).andExpect(status().isOk());

        // 清单只剩两个
        mockMvc.perform(get("/api/sessions").header("Authorization", "Bearer " + s3.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(2));
        log.info("HTTP 容量淘汰结论 EVICTED 与 REVOKED/EXPIRED 可区分");
    }

    @Test
    @DisplayName("续期后能力概要与实际权限判定一致，且会话不增多")
    void capabilitiesRemainConsistentAfterRefreshOverHttp() throws Exception {
        JsonNode first = login("alice", "password-alice", "phone-1", "mobile");
        MvcResult rotated = mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json("refreshToken", first.get("refreshToken").asText())))
                .andExpect(status().isOk()).andReturn();
        JsonNode second = objectMapper.readTree(rotated.getResponse().getContentAsString());

        // 新访问令牌仍能访问需要 reports:read 的资源（能力未丢失）
        mockMvc.perform(get("/api/protected/reports")
                        .header("Authorization", "Bearer " + second.get("accessToken").asText()))
                .andExpect(status().isOk());
        // 清单仍是 1 个会话，概要仍含 reports:read
        mockMvc.perform(get("/api/sessions").header("Authorization", "Bearer " + second.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.count").value(1))
                .andExpect(jsonPath("$.sessions[0].deviceId").value("phone-1"))
                .andExpect(jsonPath("$.sessions[0].scopes[?(@=='reports:read')]").exists());
    }
}
