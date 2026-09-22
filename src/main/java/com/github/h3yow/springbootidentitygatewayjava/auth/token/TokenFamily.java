package com.github.h3yow.springbootidentitygatewayjava.auth.token;

/**
 * 刷新令牌族（一次登录会话一个族）；族撤销后该会话下所有令牌失效。
 */
public record TokenFamily(String familyId, String username, long createdAt, boolean revoked) {

    /** 返回已撤销的新实例。 */
    public TokenFamily asRevoked() {
        return new TokenFamily(familyId, username, createdAt, true);
    }
}
