package com.trendprice.securitysite.controller;

import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

    private final UserService userService;

    public UserProfileController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me/profile")
    public Map<String, Object> getMyProfile(Authentication authentication) {
        AppUser user = userService.findByUsername(authentication.getName());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("roles", userService.getRoleNames(user.getUsername()));

        return response;
    }
}