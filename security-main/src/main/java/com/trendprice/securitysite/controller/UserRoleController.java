package com.trendprice.securitysite.controller;

import com.trendprice.securitysite.user.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/users")
public class UserRoleController {

    private final UserService userService;

    public UserRoleController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me/roles")
    public Set<String> getCurrentUserRoles(Authentication authentication) {
        requireAuthenticated(authentication);
        return userService.getRoleNames(authentication.getName());
    }

    @GetMapping("/me/roles/check")
    public Map<String, Object> checkCurrentUserRole(
            Authentication authentication,
            @RequestParam String role
    ) {
        requireAuthenticated(authentication);
        boolean hasRole = userService.hasRole(authentication.getName(), role);
        return Map.of(
                "username", authentication.getName(),
                "role", role.toUpperCase(),
                "hasRole", hasRole
        );
    }

    @GetMapping("/{username}/roles")
    public Set<String> getUserRoles(
            @PathVariable String username,
            Authentication authentication
    ) {
        requireAccess(authentication, username);
        return userService.getRoleNames(username);
    }

    @GetMapping("/{username}/roles/check")
    public Map<String, Object> checkUserRole(
            @PathVariable String username,
            @RequestParam String role,
            Authentication authentication
    ) {
        requireAccess(authentication, username);
        boolean hasRole = userService.hasRole(username, role);
        return Map.of(
                "username", username,
                "role", role.toUpperCase(),
                "hasRole", hasRole
        );
    }

    private void requireAuthenticated(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
        }
    }

    private void requireAccess(Authentication authentication, String username) {
        requireAuthenticated(authentication);

        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));

        if (!isAdmin && !authentication.getName().equals(username)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can access only your own roles");
        }
    }
}