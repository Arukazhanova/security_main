package com.trendprice.securitysite.dto.auth;

import java.util.Set;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String type,
        Long userId,
        String username,
        String email,
        Set<String> roles
) {
}