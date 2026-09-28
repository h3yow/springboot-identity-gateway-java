package com.github.h3yow.springbootidentitygatewayjava.auth.session;

import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenFamily;
import com.github.h3yow.springbootidentitygatewayjava.auth.token.TokenStore;
import com.github.h3yow.springbootidentitygatewayjava.time.Clock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;

/**
 * 多端会话管理：列出本人有效会话、按会话精准撤销。
 *
 * <p>清单规则：
 * <ul>
 *   <li>只能看到属于自己的会话（按属主严格隔离）</li>
 *   <li>已撤销（REVOKED）、已淘汰（EVICTED）、已到期（now &gt;= expiresAt）的会话一律不出现</li>
 *   <li>能力概要（roles/perms/scopes）直接取自服务端会话快照，
 *       与该会话访问令牌过权限校验、续期后重新签发所用的能力同源，结论一致</li>
 * </ul>
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final TokenStore store;
    private final Clock clock;

    public SessionService(TokenStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** 列出指定用户当前仍有效的全部会话（已撤销/淘汰/过期的不出现），按建立时间升序。 */
    public List<SessionInfo> listActiveSessions(String username) {
        long now = clock.nowMillis();
        List<SessionInfo> sessions = store.allFamilies().stream()
                .filter(f -> f.username().equals(username))
                .filter(f -> f.state() == SessionState.ACTIVE)
                .filter(f -> f.expiresAt() <= 0L || f.expiresAt() > now)
                .sorted(Comparator.comparingLong(TokenFamily::createdAt)
                        .thenComparing(TokenFamily::familyId))
                .map(this::toView)
                .toList();
        log.info("会话清单: user={}, now={}, 有效会话数={}", username, now, sessions.size());
        return sessions;
    }

    /**
     * 精准撤销指定会话；仅属主本人可操作。
     * 幂等：会话不存在/不属于该用户抛出可区分异常；已处于终止态则原样返回，不抛异常。
     *
     * @return 撤销完成后该会话的终止状态
     */
    public SessionState revokeSession(String username, String sessionId) {
        TokenFamily family = store.findFamily(sessionId)
                .orElseThrow(() -> {
                    log.warn("精准撤销拒绝: 依据=会话不存在 user={}, sessionId={}", username, sessionId);
                    return new SessionException(SessionFailureReason.SESSION_NOT_FOUND, "会话不存在或已失效");
                });
        if (!family.username().equals(username)) {
            log.warn("精准撤销拒绝: 依据=会话不属于当前用户 user={}, owner={}, sessionId={}",
                    username, family.username(), sessionId);
            throw new SessionException(SessionFailureReason.SESSION_NOT_OWNED, "无权操作他人会话");
        }
        return store.withFamilyLock(sessionId, fid -> {
            TokenFamily current = store.findFamily(fid).orElseThrow(() ->
                    new SessionException(SessionFailureReason.SESSION_NOT_FOUND, "会话不存在或已失效"));
            if (current.state() == SessionState.ACTIVE) {
                store.putFamily(current.asRevoked());
                log.info("精准撤销成功: user={}, sessionId={}", username, fid);
            } else {
                // 已撤销/已淘汰：重复操作结论一致，不抛异常、不改变先到先得的终态
                log.info("精准撤销幂等返回: user={}, sessionId={}, 当前终态={}", username, fid, current.state());
            }
            return store.findFamily(fid).map(TokenFamily::state).orElse(SessionState.REVOKED);
        });
    }

    private SessionInfo toView(TokenFamily f) {
        return new SessionInfo(
                f.familyId(), f.username(),
                f.clientInfo().deviceType(), f.clientInfo().deviceName(), f.clientInfo().clientId(),
                f.createdAt(), f.lastActiveAt(), f.expiresAt(),
                f.roles(), f.permissions(), f.scopes());
    }
}
