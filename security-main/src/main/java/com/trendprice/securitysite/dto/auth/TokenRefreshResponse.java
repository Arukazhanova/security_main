package com.trendprice.securitysite.dto.auth;

public record TokenRefreshResponse(
        String accessToken,
        String type
) {
}