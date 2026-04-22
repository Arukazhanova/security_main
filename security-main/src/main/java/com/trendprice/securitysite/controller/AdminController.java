package com.trendprice.securitysite.controller;

import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
import jakarta.validation.constraints.NotBlank;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    public record UserSummary(
            Long id,
            String username,
            String email,
            Boolean emailVerified,
            Boolean enabled,
            Boolean blocked,
            List<String> roles
    ) {}

    public record ChangeRoleRequest(@NotBlank String role) {}

    public record MessageResponse(String message) {}

    @GetMapping("/users")
    public List<UserSummary> getAllUsers() {
        return userService.findAllUsers().stream()
                .map(user -> new UserSummary(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getEmailVerified(),
                        user.isEnabled(),
                        user.getBlocked(),
                        user.getRoles().stream().map(r -> r.getName().name()).toList()
                ))
                .toList();
    }

    @PatchMapping("/users/{id}/block")
    public MessageResponse blockUser(@PathVariable Long id) {
        userService.blockUser(id);
        return new MessageResponse("User blocked");
    }

    @PatchMapping("/users/{id}/unblock")
    public MessageResponse unblockUser(@PathVariable Long id) {
        userService.unblockUser(id);
        return new MessageResponse("User unblocked");
    }

    @PatchMapping("/users/{id}/role")
    public MessageResponse changeRole(@PathVariable Long id, @RequestBody ChangeRoleRequest req) {
        userService.changeRole(id, req.role());
        return new MessageResponse("User role updated");
    }
}