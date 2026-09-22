package com.github.h3yow.springbootidentitygatewayjava.web.dto;

import com.github.h3yow.springbootidentitygatewayjava.token.TokenPair;

import java.time.Instant;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        String sessionId,
        String tokenType,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
    public static TokenResponse from(TokenPair pair) {
        return new TokenResponse(
                pair.accessToken(),
                pair.refreshToken(),
                pair.sessionId(),
                "Bearer",
                pair.accessTokenExpiresAt(),
                pair.refreshTokenExpiresAt());
    }
}
