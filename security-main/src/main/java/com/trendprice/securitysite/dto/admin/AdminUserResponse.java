package com.trendprice.securitysite.dto.admin;

import com.trendprice.securitysite.user.AppUser;

import java.util.List;

public record AdminUserResponse(
        Long id,
        String username,
        String email,
        Boolean emailVerified,
        Boolean enabled,
        Boolean blocked,
        List<String> roles
) {
    public static AdminUserResponse from(AppUser user) {
        return new AdminUserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getEmailVerified(),
                user.isEnabled(),
                user.getBlocked(),
                user.getRoles().stream()
                        .map(role -> role.getName().name())
                        .sorted()
                        .toList()
        );
    }
}