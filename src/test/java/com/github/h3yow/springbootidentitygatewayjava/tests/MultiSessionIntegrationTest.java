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

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 多端会话管理的端到端 HTTP 测试：
 * 多端清单与属主隔离、按会话精准下线、容量淘汰 LRU、被淘汰会话 401 EVICTED、
 * 续期后能力概要与实际权限判定一致、越权撤销 403。
 * 时钟可控，结论离线可重复。
 */
@SpringBootTest(properties = {
        "auth.max-failures=5",
        "auth.otp-ttl-millis=300000",
        "auth.access-token-ttl-millis=900000",
        "auth.refresh-token-ttl-millis=600000",
        "auth.max-sessions-per-user=3",
        "auth.expose-otp-for-local-dev=true"
})
@AutoConfigureMockMvc
class MultiSessionIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(MultiSessionIntegrationTest.class);
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
        ((MutableClock) clock).setNow(T0);
        otpStore.clear();
        failureCounter.clear();
        tokenStore.clear();
    }

    /** 第一步（password）/第二步（otp）请求体：extras 为 null 表示第一步，否则为第二步。 */
    private String passwordStepJson(String username, String secret, Map<String, String> extras) throws Exception {
        var node = objectMapper.createObjectNode();
        node.put("username", username);
        // 第一步用 password，第二步用 otp；这里由调用方控制字段名更清晰，故显式区分
        if (extras == null) {
            node.put("password", secret);
        } else {
            node.put("otp", secret);
            extras.forEach(node::put);
        }
        return objectMapper.writeValueAsString(node);
    }

    /** 完成完整两步登录并返回令牌 JSON。 */
    private JsonNode fullLogin(String username, String password, String device, String clientId) throws Exception {
        Map<String, String> extras = new LinkedHashMap<>();
        if (device != null) {
            extras.put("deviceType", device);
            extras.put("deviceName", device + "-name");
        }
        if (clientId != null) {
            extras.put("clientId", clientId);
        }
        MvcResult step1 = mockMvc.perform(post("/api/auth/login/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordStepJson(username, password, null)))
                .andExpect(status().isOk()).andReturn();
        String otp = objectMapper.readTree(step1.getResponse().getContentAsString())
                .get("otpForLocalDev").asText();
        MvcResult step2 = mockMvc.perform(post("/api/auth/login/otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordStepJson(username, otp, extras)))
                .andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(step2.getResponse().getContentAsString());
    }

    private String bearer(JsonNode tokens) {
        return "Bearer " + tokens.get("accessToken").asText();
    }

    private JsonNode listSessions(String accessToken) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk()).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("多端并存：清单区分设备/客户端与时间，且只能看到自己的会话")
    void multiDeviceListingAndIsolation() throws Exception {
        JsonNode phone = fullLogin("alice", "password-alice", "phone", "ios-app");
        ((MutableClock) clock).advance(10_000L);
        JsonNode laptop = fullLogin("alice", "password-alice", "laptop", "web-browser");
        JsonNode bob = fullLogin("bob", "password-bob", "phone", "ios-app");

        JsonNode aliceSessions = listSessions(phone.get("accessToken").asText());
        log.info("alice 清单: {}", aliceSessions);
        assertTrue(aliceSessions.isArray());
        org.junit.jupiter.api.Assertions.assertEquals(2, aliceSessions.size());
        JsonNode phoneView = findSessionByDevice(aliceSessions, "phone");
        JsonNode laptopView = findSessionByDevice(aliceSessions, "laptop");
        org.junit.jupiter.api.Assertions.assertEquals("ios-app", phoneView.get("clientId").asText());
        org.junit.jupiter.api.Assertions.assertEquals("web-browser", laptopView.get("clientId").asText());
        org.junit.jupiter.api.Assertions.assertTrue(
                laptopView.get("createdAt").asLong() >= phoneView.get("createdAt").asLong());

        // bob 只能看到自己的 1 个会话
        JsonNode bobSessions = listSessions(bob.get("accessToken").asText());
        org.junit.jupiter.api.Assertions.assertEquals(1, bobSessions.size());
        org.junit.jupiter.api.Assertions.assertEquals("bob", bobSessions.get(0).get("username").asText());

        // 未认证访问清单 -> 401
        mockMvc.perform(get("/api/sessions")).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("按会话精准下线：目标会话 401 消失，其它会话照常；重复撤销结论一致")
    void revokeSingleSession() throws Exception {
        JsonNode phone = fullLogin("alice", "password-alice", "phone", "ios-app");
        JsonNode laptop = fullLogin("alice", "password-alice", "laptop", "web");
        String phoneSessionId = findSessionByDevice(
                listSessions(phone.get("accessToken").asText()), "phone").get("sessionId").asText();
        String laptopSessionId = findSessionByDevice(
                listSessions(laptop.get("accessToken").asText()), "laptop").get("sessionId").asText();

        // 用 laptop 的令牌撤销 phone 会话（属主相同，允许）
        mockMvc.perform(post("/api/sessions/" + phoneSessionId + "/revoke")
                        .header("Authorization", bearer(laptop)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("REVOKED"));

        // phone 访问与续期均被拒
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(phone)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + phone.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("REVOKED"));

        // phone 已从清单消失，laptop 仍在且可用
        JsonNode remaining = listSessions(laptop.get("accessToken").asText());
        org.junit.jupiter.api.Assertions.assertEquals(1, remaining.size());
        org.junit.jupiter.api.Assertions.assertEquals(laptopSessionId, remaining.get(0).get("sessionId").asText());
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(laptop)))
                .andExpect(status().isOk());

        // 重复撤销 phone：仍 200 且 state=REVOKED，不报错
        mockMvc.perform(post("/api/sessions/" + phoneSessionId + "/revoke")
                        .header("Authorization", bearer(laptop)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("REVOKED"));
    }

    @Test
    @DisplayName("不能撤销他人会话：403 SESSION_NOT_OWNED，目标会话不受影响")
    void cannotRevokeOthersSession() throws Exception {
        JsonNode alice = fullLogin("alice", "password-alice", "phone", "ios");
        JsonNode bob = fullLogin("bob", "password-bob", "phone", "ios");
        String aliceSessionId = listSessions(alice.get("accessToken").asText()).get(0).get("sessionId").asText();

        mockMvc.perform(post("/api/sessions/" + aliceSessionId + "/revoke").header("Authorization", bearer(bob)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("SESSION_NOT_OWNED"));

        // alice 会话仍然有效
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(alice)))
                .andExpect(status().isOk());
        org.junit.jupiter.api.Assertions.assertEquals(1,
                listSessions(alice.get("accessToken").asText()).size());
    }

    @Test
    @DisplayName("容量上限：第四次登录淘汰最久未活跃会话，被淘汰者 401 EVICTED，其余照常")
    void capacityEvictionHttp() throws Exception {
        JsonNode s1 = fullLogin("alice", "password-alice", "dev-1", "c1");
        ((MutableClock) clock).advance(1000L);
        JsonNode s2 = fullLogin("alice", "password-alice", "dev-2", "c2");
        ((MutableClock) clock).advance(1000L);
        // s1 活跃一次，使其不是最久未活跃
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(s1)))
                .andExpect(status().isOk());
        ((MutableClock) clock).advance(1000L);
        JsonNode s3 = fullLogin("alice", "password-alice", "dev-3", "c3");
        org.junit.jupiter.api.Assertions.assertEquals(3,
                listSessions(s3.get("accessToken").asText()).size());
        ((MutableClock) clock).advance(1000L);
        JsonNode s4 = fullLogin("alice", "password-alice", "dev-4", "c4");

        // s2 最久未活跃，被淘汰：访问 401
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(s2)))
                .andExpect(status().isUnauthorized());
        // 续期 EVICTED
        mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + s2.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("EVICTED"));

        // 清单只剩 3 个，且不含 s2
        JsonNode sessions = listSessions(s4.get("accessToken").asText());
        org.junit.jupiter.api.Assertions.assertEquals(3, sessions.size());
        for (var node : sessions) {
            org.junit.jupiter.api.Assertions.assertNotEquals("dev-2", node.get("deviceType").asText());
        }
        // s1、s3、s4 仍可用
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(s1))).andExpect(status().isOk());
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(s3))).andExpect(status().isOk());
        mockMvc.perform(get("/api/protected/profile").header("Authorization", bearer(s4))).andExpect(status().isOk());
    }

    @Test
    @DisplayName("续期后能力概览与实际权限判定一致，且能力不丢失")
    void capabilityConsistencyAfterRefreshHttp() throws Exception {
        JsonNode first = fullLogin("admin", "password-admin", "pc", "web");
        String sessionId = listSessions(first.get("accessToken").asText()).get(0).get("sessionId").asText();

        MvcResult refreshed = mockMvc.perform(post("/api/auth/token/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + first.get("refreshToken").asText() + "\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode second = objectMapper.readTree(refreshed.getResponse().getContentAsString());

        // 续期后清单能力概要仍是完整管理员能力
        JsonNode sessions = listSessions(second.get("accessToken").asText());
        JsonNode session = findSession(sessions, sessionId);
        org.junit.jupiter.api.Assertions.assertTrue(session.get("roles").toString().contains("admin"));
        org.junit.jupiter.api.Assertions.assertTrue(session.get("permissions").toString().contains("user:write"));
        org.junit.jupiter.api.Assertions.assertTrue(session.get("scopes").toString().contains("reports:read"));

        // 同一能力可通过实际权限边界：admin 入口与 reports 范围入口均 200
        mockMvc.perform(get("/api/protected/admin").header("Authorization", bearer(second)))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/protected/reports").header("Authorization", bearer(second)))
                .andExpect(status().isOk());
    }

    private JsonNode findSession(JsonNode sessions, String sessionId) {
        for (var node : sessions) {
            if (node.get("sessionId").asText().equals(sessionId)) {
                return node;
            }
        }
        throw new IllegalStateException("未找到会话: " + sessionId);
    }

    private JsonNode findSessionByDevice(JsonNode sessions, String deviceType) {
        for (var node : sessions) {
            if (deviceType.equals(node.get("deviceType").asText())) {
                return node;
            }
        }
        throw new IllegalStateException("未找到设备会话: " + deviceType);
    }
}
