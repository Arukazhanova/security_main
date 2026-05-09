package com.trendprice.securitysite.dto.auth;

public record VerificationResponse(
        String message,
        boolean emailVerified,
        String username
) {
}