package com.github.h3yow.springbootidentitygatewayjava.auth.access;

import com.github.h3yow.springbootidentitygatewayjava.auth.token.AccessTokenClaims;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenException;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenRejectionReason;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Arrays;

/**
 * 统一权限判定：认证 -&gt; 角色/权限 -&gt; 范围；各受保护入口共用同一套逻辑。
 *
 * <p>三类拒绝结论可区分：
 * <ul>
 *   <li>{@link AccessDenialReason#UNAUTHENTICATED}：无令牌或令牌无效/过期/撤销</li>
 *   <li>{@link AccessDenialReason#FORBIDDEN_NO_PERMISSION}：已认证，但角色与权限均不满足</li>
 *   <li>{@link AccessDenialReason#FORBIDDEN_INSUFFICIENT_SCOPE}：角色/权限满足，但令牌范围不覆盖</li>
 * </ul>
 * 未标注 {@link RequireAccess} 的入口由拦截器按 {@link AccessDenialReason#DEFAULT_DENY} 拒绝。
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);
    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokenService;

    public AccessControlService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * 对一次受保护访问做判定。
     *
     * @param authorizationHeader 原始 Authorization 头（可为 null）
     * @param requirement         方法/类上的保护要求（可为 null，表示默认拒绝，由调用方处理）
     */
    public AccessDecision decide(String authorizationHeader, RequireAccess requirement) {
        String token = extractBearer(authorizationHeader);
        if (token == null) {
            log.info("访问判定拒绝: 依据=缺少 Authorization: Bearer 令牌");
            return AccessDecision.deny(AccessDenialReason.UNAUTHENTICATED, "缺少访问令牌");
        }
        AccessTokenClaims claims;
        try {
            claims = tokenService.authenticate(token);
        } catch (TokenException ex) {
            log.info("访问判定拒绝: 依据=令牌校验失败 reason={}, message={}", ex.getReason(), ex.getMessage());
            return AccessDecision.deny(AccessDenialReason.UNAUTHENTICATED,
                    "访问令牌无效: " + ex.getReason());
        }
        return authorize(claims, requirement);
    }

    /** 已认证声明基础上的角色/权限/范围判定。 */
    AccessDecision authorize(AccessTokenClaims claims, RequireAccess requirement) {
        boolean roleOk = anyMatches(requirement.roles(), claims.roles());
        boolean permissionOk = anyMatches(requirement.permissions(), claims.permissions());
        boolean scopeRequired = requirement.scopes().length > 0;
        boolean scopeOk = !scopeRequired || anyMatches(requirement.scopes(), claims.scopes());

        log.info("访问判定输入: user={}, family={}, 要求roles={}, 要求perms={}, 要求scopes={}; "
                        + "持有roles={}, 持有perms={}, 持有scopes={}; 判定 roleOk={}, permOk={}, scopeOk={}",
                claims.username(), claims.familyId(),
                Arrays.toString(requirement.roles()), Arrays.toString(requirement.permissions()),
                Arrays.toString(requirement.scopes()),
                claims.roles(), claims.permissions(), claims.scopes(), roleOk, permissionOk, scopeOk);

        // 角色与权限要求：未声明的维度不参与；只要声明的维度全部满足（至少一个命中）即通过
        boolean roleRequirementMet = requirement.roles().length == 0 || roleOk;
        boolean permissionRequirementMet = requirement.permissions().length == 0 || permissionOk;
        if (!roleRequirementMet || !permissionRequirementMet) {
            return AccessDecision.deny(AccessDenialReason.FORBIDDEN_NO_PERMISSION,
                    "角色或权限不满足: 需要 roles=" + Arrays.toString(requirement.roles())
                            + " permissions=" + Arrays.toString(requirement.permissions()));
        }
        if (scopeRequired && !scopeOk) {
            return AccessDecision.deny(AccessDenialReason.FORBIDDEN_INSUFFICIENT_SCOPE,
                    "令牌范围不足: 需要 scopes=" + Arrays.toString(requirement.scopes())
                            + " 持有=" + claims.scopes());
        }
        return AccessDecision.permit(claims, "角色/权限/范围均满足");
    }

    private static String extractBearer(String header) {
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    private static boolean anyMatches(String[] required, java.util.Set<String> held) {
        for (String item : required) {
            if (held.contains(item)) {
                return true;
            }
        }
        return false;
    }
}
