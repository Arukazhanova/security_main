package com.trendprice.securitysite.controller;

import com.trendprice.securitysite.dto.admin.AdminUserResponse;
import com.trendprice.securitysite.dto.admin.ChangeUserRoleRequest;
import com.trendprice.securitysite.dto.common.MessageResponse;
import com.trendprice.securitysite.user.UserService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
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

    @GetMapping("/users")
    public List<AdminUserResponse> getAllUsers() {
        return userService.findAllUsers().stream()
                .map(AdminUserResponse::from)
                .toList();
    }

    @PatchMapping("/users/{id}/block")
    public MessageResponse blockUser(
            @PathVariable Long id,
            Authentication authentication
    ) {
        userService.blockUser(id, authentication.getName());
        return new MessageResponse("User blocked successfully");
    }

    @PatchMapping("/users/{id}/unblock")
    public MessageResponse unblockUser(@PathVariable Long id) {
        userService.unblockUser(id);
        return new MessageResponse("User unblocked successfully");
    }

    @PatchMapping("/users/{id}/role")
    public MessageResponse changeRole(
            @PathVariable Long id,
            @Valid @RequestBody ChangeUserRoleRequest request,
            Authentication authentication
    ) {
        userService.changeRole(id, request.role(), authentication.getName());
        return new MessageResponse("User role updated successfully");
    }
}