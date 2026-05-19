package com.trendprice.securitysite.dto.auth;

public record RegisterResponse(
        String message,
        String verificationLink,
        String verificationToken
) {
    public RegisterResponse(String message) {
        this(message, null, null);
    }
}