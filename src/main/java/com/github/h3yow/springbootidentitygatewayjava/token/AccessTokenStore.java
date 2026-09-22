package com.github.h3yow.springbootidentitygatewayjava.token;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** 访问令牌记录的内存存储；会话撤销后其中记录不再被接受。 */
@Component
public class AccessTokenStore {

    private final ConcurrentHashMap<String, StoredAccessToken> tokens = new ConcurrentHashMap<>();

    public void put(StoredAccessToken record) {
        tokens.put(record.tokenId(), record);
    }

    public Optional<StoredAccessToken> find(String tokenId) {
        if (tokenId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokens.get(tokenId));
    }

    /** 测试辅助：清除全部记录。 */
    public void clear() {
        tokens.clear();
    }
}
