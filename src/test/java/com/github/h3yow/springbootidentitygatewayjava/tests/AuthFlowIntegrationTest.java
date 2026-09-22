package com.github.h3yow.springbootidentitygatewayjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 完整 HTTP 闭环集成测试：两步登录 -> 携带令牌访问 -> 刷新一次性/重放吊销 -> 登出失效。
 * 使用内存种子用户（application.properties 中的演示凭据），无网络与外部服务。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowIntegrationTest.class);
    private final ObjectMapper json = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private MvcResult postJson(String url, Map<String, String> body) throws Exception {
        return mockMvc.perform(post(url)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(body)))
                .andReturn();
    }

    private JsonNode jsonOf(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void fullLoginAccessRefreshReplayLogoutLoop() throws Exception {
        // 1) 错误密码
        MvcResult bad = postJson("/api/auth/login/password", Map.of("username", "alice", "password", "nope"));
        log.info("[步骤1] 错误密码 -> status={}, body={}",
                bad.getResponse().getStatus(), bad.getResponse().getContentAsString());
        org.junit.jupiter.api.Assertions.assertEquals(401, bad.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertEquals("LOGIN_BAD_CREDENTIALS", jsonOf(bad).get("code").asText());

        // 2) 正确密码，拿到 pendingToken 与演示回显的 OTP
        MvcResult step1 = postJson("/api/auth/login/password",
                Map.of("username", "alice", "password", "alice-pw"));
        JsonNode step1Body = jsonOf(step1);
        String pendingToken = step1Body.get("pendingToken").asText();
        String otp = step1Body.get("otpHint").asText();
        log.info("[步骤2] 正确密码 -> pendingTokenTail=…{}, otp={}",
                pendingToken.substring(pendingToken.length() - 6), otp);
        org.junit.jupiter.api.Assertions.assertEquals(200, step1.getResponse().getStatus());

        // 3) 错误 OTP
        MvcResult wrongOtp = postJson("/api/auth/login/otp",
                Map.of("pendingToken", pendingToken, "otp", "000000"));
        log.info("[步骤3] 错误 OTP -> status={}, code={}",
                wrongOtp.getResponse().getStatus(), jsonOf(wrongOtp).get("code").asText());
        org.junit.jupiter.api.Assertions.assertEquals("OTP_INVALID", jsonOf(wrongOtp).get("code").asText());

        // 4) 同一 pendingToken 再次提交（已消费）-> OTP_REPLAYED
        MvcResult replayedOtp = postJson("/api/auth/login/otp",
                Map.of("pendingToken", pendingToken, "otp", otp));
        log.info("[步骤4] 重复 OTP -> status={}, code={}",
                replayedOtp.getResponse().getStatus(), jsonOf(replayedOtp).get("code").asText());
        org.junit.jupiter.api.Assertions.assertEquals(409, replayedOtp.getResponse().getStatus());
        org.junit.jupiter.api.Assertions.assertEquals("OTP_REPLAYED", jsonOf(replayedOtp).get("code").asText());

        // 5) 重新走完整两步登录
        MvcResult s1 = postJson("/api/auth/login/password", Map.of("username", "alice", "password", "alice-pw"));
        JsonNode s1b = jsonOf(s1);
        MvcResult s2 = postJson("/api/auth/login/otp",
                Map.of("pendingToken", s1b.get("pendingToken").asText(), "otp", s1b.get("otpHint").asText()));
        JsonNode tokens = jsonOf(s2);
        String access = tokens.get("accessToken").asText();
        String refresh = tokens.get("refreshToken").asText();
        log.info("[步骤5] 完整登录成功 -> sessionId={}", tokens.get("sessionId").asText());

        // 6) 无令牌访问受保护资源 -> 401 TOKEN_MISSING
        mockMvc.perform(get("/api/resources/orders"))
                .andExpect(status().isUnauthorized());
        log.info("[步骤6] 无令牌访问 orders -> 401 TOKEN_MISSING（符合预期）");

        // 7) 携带令牌访问有权限的 orders -> 200；访问无权限的 admin -> 403
        mockMvc.perform(get("/api/resources/orders").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
        MvcResult denied = mockMvc.perform(get("/api/resources/admin").header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden()).andReturn();
        log.info("[步骤7] orders=200，admin -> code={}（alice 无 admin 角色）",
                jsonOf(denied).get("code").asText());
        org.junit.jupiter.api.Assertions.assertEquals("ACCESS_DENIED_ROLE", jsonOf(denied).get("code").asText());

        // 8) 刷新成功
        MvcResult refreshed = postJson("/api/auth/refresh", Map.of("refreshToken", refresh));
        JsonNode newTokens = jsonOf(refreshed);
        String newRefresh = newTokens.get("refreshToken").asText();
        log.info("[步骤8] 刷新成功 -> newSessionId={}", newTokens.get("sessionId").asText());
        org.junit.jupiter.api.Assertions.assertEquals(200, refreshed.getResponse().getStatus());

        // 9) 旧刷新令牌重放 -> 401 REFRESH_REPLAYED，且整族失效
        MvcResult replay = postJson("/api/auth/refresh", Map.of("refreshToken", refresh));
        log.info("[步骤9] 旧 refreshToken 重放 -> status={}, code={}",
                replay.getResponse().getStatus(), jsonOf(replay).get("code").asText());
        org.junit.jupiter.api.Assertions.assertEquals("REFRESH_REPLAYED", jsonOf(replay).get("code").asText());

        MvcResult newRefreshFails = postJson("/api/auth/refresh", Map.of("refreshToken", newRefresh));
        log.info("[步骤10] 重放后新 refreshToken 也失效 -> code={}",
                jsonOf(newRefreshFails).get("code").asText());
        org.junit.jupiter.api.Assertions.assertEquals("REFRESH_REPLAYED",
                jsonOf(newRefreshFails).get("code").asText());

        // 11) 重新登录后登出，令牌立即失效
        MvcResult l1 = postJson("/api/auth/login/password", Map.of("username", "alice", "password", "alice-pw"));
        JsonNode l1b = jsonOf(l1);
        MvcResult l2 = postJson("/api/auth/login/otp",
                Map.of("pendingToken", l1b.get("pendingToken").asText(), "otp", l1b.get("otpHint").asText()));
        JsonNode tk = jsonOf(l2);
        String a2 = tk.get("accessToken").asText();
        String r2 = tk.get("refreshToken").asText();
        mockMvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + a2))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + a2))
                .andExpect(status().isOk());
        MvcResult afterLogout = mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + a2))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("[步骤11] 登出后原 accessToken -> code={}", jsonOf(afterLogout).get("code").asText());
        org.junit.jupiter.api.Assertions.assertEquals("TOKEN_REVOKED", jsonOf(afterLogout).get("code").asText());
        MvcResult refreshAfterLogout = postJson("/api/auth/refresh", Map.of("refreshToken", r2));
        org.junit.jupiter.api.Assertions.assertEquals("REFRESH_REPLAYED",
                jsonOf(refreshAfterLogout).get("code").asText());
        log.info("[步骤11] 登出后 refreshToken -> code=REFRESH_REPLAYED（符合预期）");
    }
}
