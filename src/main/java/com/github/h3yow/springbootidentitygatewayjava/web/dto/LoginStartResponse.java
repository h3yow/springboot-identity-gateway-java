package com.github.h3yow.springbootidentitygatewayjava.web.dto;

import java.time.Instant;

public record LoginStartResponse(String pendingToken, String otpHint, Instant otpExpiresAt) {
}
