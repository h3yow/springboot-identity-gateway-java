package com.github.h3yow.springbootidentitygatewayjava.web.dto;

public record OtpVerifyRequest(String pendingToken, String otp) {
}
