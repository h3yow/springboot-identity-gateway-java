package com.github.h3yow.springbootidentitygatewayjava.token;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 刷新会话内存存储。
 * - byId：会话 id -> 会话；
 * - refreshIndex：当前有效刷新令牌 -> 会话 id（一次性，轮换后旧键摘除）；
 * - rotatedIndex：已被轮换掉的旧刷新令牌 -> 会话 id（用于重放检测与整族吊销）。
 */
@Component
public class SessionStore {

    private final ConcurrentHashMap<String, TokenSession> byId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> refreshIndex = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> rotatedIndex = new ConcurrentHashMap<>();

    public void put(TokenSession session, String refreshToken) {
        byId.put(session.sessionId(), session);
        refreshIndex.put(refreshToken, session.sessionId());
    }

    public Optional<TokenSession> findById(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(sessionId));
    }

    public Optional<TokenSession> findByRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        String sessionId = refreshIndex.get(refreshToken);
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(sessionId));
    }

    /** 用已轮换掉的旧刷新令牌反查会话（重放检测）。 */
    public Optional<TokenSession> findByRotatedToken(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        String sessionId = rotatedIndex.get(refreshToken);
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byId.get(sessionId));
    }

    /** 轮换索引：旧令牌移入重放索引，新令牌成为当前令牌。 */
    public void rebindRefresh(String oldRefreshToken, String newRefreshToken, String sessionId) {
        if (oldRefreshToken != null) {
            refreshIndex.remove(oldRefreshToken, sessionId);
            rotatedIndex.put(oldRefreshToken, sessionId);
        }
        refreshIndex.put(newRefreshToken, sessionId);
    }

    /** 撤销索引：摘除当前刷新令牌键，使其无法再按有效令牌定位。 */
    public void unbindRefresh(String refreshToken, String sessionId) {
        if (refreshToken != null) {
            refreshIndex.remove(refreshToken, sessionId);
        }
    }

    public void clear() {
        byId.clear();
        refreshIndex.clear();
        rotatedIndex.clear();
    }
}
