package com.trendprice.securitysite.controller;

import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

    private final UserService userService;

    public UserProfileController(UserService userService) {
        this.userService = userService;
    }

    public record UpdateProfileRequest(
            @Size(max = 80) String firstName,
            @Size(max = 80) String lastName,
            @Size(max = 30) String phoneNumber,
            @Size(max = 20) String dateOfBirth
    ) {}

    @GetMapping("/me/profile")
    public Map<String, Object> getMyProfile(Authentication authentication) {
        AppUser user = userService.findByUsername(authentication.getName());

        return toProfileResponse(user);
    }

    @PutMapping("/me/profile")
    public Map<String, Object> updateMyProfile(
            Authentication authentication,
            @Valid @RequestBody UpdateProfileRequest request
    ) {
        AppUser user = userService.updateProfile(
                authentication.getName(),
                request.firstName(),
                request.lastName(),
                request.phoneNumber(),
                request.dateOfBirth()
        );

        return toProfileResponse(user);
    }

    private Map<String, Object> toProfileResponse(AppUser user) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("username", user.getUsername());
        response.put("email", user.getEmail());
        response.put("roles", userService.getRoleNames(user.getUsername()));
        response.put("firstName", user.getFirstName());
        response.put("lastName", user.getLastName());
        response.put("phoneNumber", user.getPhoneNumber());
        response.put("dateOfBirth", user.getDateOfBirth());

        return response;
    }
}