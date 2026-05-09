package com.trendprice.securitysite.dto.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ChangeUserRoleRequest(
        @NotBlank(message = "Role is required")
        @Pattern(
                regexp = "^(USER|ADMIN|user|admin)$",
                message = "Role must be USER or ADMIN"
        )
        String role
) {
}