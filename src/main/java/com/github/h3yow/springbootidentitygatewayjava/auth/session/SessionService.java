package com.github.h3yow.springbootidentitygatewayjava.auth.session;

import com.github.h3yow.springbootidentitygatewayjava.auth.token.SessionState;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenFamily;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenService;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenStore;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * 多端会话管理：查看本人有效会话清单、按会话精准下线。
 *
 * <p>清单规则：只能看到自己的会话；已过期、被撤销、被淘汰的会话不出现；
 * 清单中的 roles/permissions/scopes 直接取自会话（令牌族）上的登录能力快照，
 * 与该会话真正过权限校验时使用的能力同源，续期后保持不变。
 *
 * <p>撤销规则：在族锁内完成“属主校验 + 终态转换”，与续期/淘汰互斥；
 * 重复撤销对同一会话给出一致结论（幂等，不抛异常、不翻转终态）。
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final TokenService tokenService;
    private final TokenStore tokenStore;
    private final Clock clock;

    public SessionService(TokenService tokenService, TokenStore tokenStore, Clock clock) {
        this.tokenService = tokenService;
        this.tokenStore = tokenStore;
        this.clock = clock;
    }

    /** 列出指定用户当前全部有效会话，按最近活跃时间倒序（最活跃在前）。 */
    public List<SessionInfo> listSessions(String username) {
        long now = clock.nowMillis();
        List<SessionInfo> sessions = tokenService.familiesOf(username).stream()
                .filter(family -> tokenService.isSessionEffective(family, now))
                .map(this::toInfo)
                .sorted(Comparator.comparingLong(SessionInfo::lastActiveAt).reversed()
                        .thenComparing(SessionInfo::sessionId))
                .toList();
        log.info("会话清单: user={}, 有效会话数={}", username, sessions.size());
        return sessions;
    }

    /**
     * 撤销指定会话；仅属主可操作。
     *
     * @return true 表示本次调用将 ACTIVE 会话转为撤销；false 表示此前已是终态（结论一致）
     * @throws SessionException 会话不存在或不属于该用户（统一结论，避免会话枚举）
     */
    public boolean revokeSession(String username, String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            throw new SessionException("缺少会话标识");
        }
        return tokenStore.withFamilyLock(sessionId, fid -> {
            TokenFamily family = tokenService.findFamily(fid)
                    .filter(f -> username.equals(f.username()))
                    .orElseThrow(() -> new SessionException("会话不存在或无权操作: " + fid));
            if (family.state() == SessionState.ACTIVE) {
                tokenStore.revokeFamily(fid);
                log.info("按会话精准下线: user={}, family={}, 依据=用户主动撤销该会话", username, fid);
                return true;
            }
            log.info("重复撤销会话: user={}, family={}, 当前终态={}, 结论=保持一致不再变更",
                    username, fid, family.state());
            return false;
        });
    }

    private SessionInfo toInfo(TokenFamily family) {
        return new SessionInfo(
                family.familyId(),
                family.deviceId(),
                family.deviceName(),
                family.clientId(),
                family.createdAt(),
                family.lastActiveAt(),
                family.lastActiveAt() + tokenService.refreshTtlMillis(),
                immutableCopy(family.roles()),
                immutableCopy(family.permissions()),
                immutableCopy(family.scopes()));
    }

    private static Set<String> immutableCopy(Set<String> values) {
        return values == null ? Set.of() : Set.copyOf(values);
    }
}
