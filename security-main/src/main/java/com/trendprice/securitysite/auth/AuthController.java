package com.trendprice.securitysite.auth;

import com.trendprice.securitysite.security.JwtService;
import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final EmailVerificationService emailVerificationService;

    public AuthController(
            UserService userService,
            JwtService jwtService,
            AuthenticationManager authManager,
            EmailVerificationService emailVerificationService
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authManager = authManager;
        this.emailVerificationService = emailVerificationService;
    }

    public record RegisterRequest(
            @NotBlank @Size(min = 3, max = 60) String username,
            @NotBlank @Email @Size(max = 120) String email,
            @NotBlank @Size(min = 6, max = 100) String password
    ) {}

    public record LoginRequest(
            @NotBlank String username,
            @NotBlank String password
    ) {}

    public record AuthResponse(String token, String type) {}

    public record RegisterResponse(
            String message,
            String verificationToken,
            String verificationUrl
    ) {}

    public record VerificationResponse(
            String message,
            boolean emailVerified,
            String username
    ) {}

    @PostMapping("/register")
    public RegisterResponse register(@Valid @RequestBody RegisterRequest req) {
        AppUser user = userService.register(req.username(), req.password(), req.email());
        EmailVerificationToken verificationToken = emailVerificationService.createToken(user);

        return new RegisterResponse(
                "Registration successful. Confirm your email before login.",
                verificationToken.getToken(),
                "/api/auth/verify-email?token=" + verificationToken.getToken()
        );
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password())
            );
            AppUser user = (AppUser) auth.getPrincipal();
            String token = jwtService.generateToken(user.getUsername());
            return new AuthResponse(token, "Bearer");
        } catch (DisabledException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Email is not verified");
        } catch (BadCredentialsException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
    }

    @GetMapping("/verify-email")
    public VerificationResponse verifyEmail(@RequestParam String token) {
        AppUser user = emailVerificationService.confirmEmail(token);
        return new VerificationResponse("Email successfully confirmed", true, user.getUsername());
    }
}