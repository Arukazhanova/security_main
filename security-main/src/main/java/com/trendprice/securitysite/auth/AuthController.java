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
import org.springframework.security.authentication.LockedException;
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
    private final PasswordResetService passwordResetService;

    public AuthController(
            UserService userService,
            JwtService jwtService,
            AuthenticationManager authManager,
            EmailVerificationService emailVerificationService,
            PasswordResetService passwordResetService
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authManager = authManager;
        this.emailVerificationService = emailVerificationService;
        this.passwordResetService = passwordResetService;
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

    public record AuthResponse(
            String token,
            String type,
            Long userId,
            String username,
            String email,
            java.util.Set<String> roles
    ) {}

    public record RegisterResponse(String message) {}

    public record VerificationResponse(
            String message,
            boolean emailVerified,
            String username
    ) {}

    public record ResendVerificationRequest(
            @NotBlank @Email String email
    ) {}

    public record ForgotPasswordRequest(
            @NotBlank @Email String email
    ) {}

    public record ResetPasswordRequest(
            @NotBlank String token,
            @NotBlank @Size(min = 8, max = 100) String newPassword
    ) {}

    public record MessageResponse(String message) {}

    @PostMapping("/register")
    public RegisterResponse register(@Valid @RequestBody RegisterRequest req) {
        System.out.println("REGISTER ENDPOINT HIT");
        AppUser user = userService.register(req.username(), req.password(), req.email());
        emailVerificationService.sendVerificationEmail(user);
        return new RegisterResponse("Registration successful. Check your email to verify your account.");
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest req) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.username(), req.password())
            );

            AppUser user = (AppUser) auth.getPrincipal();
            String token = jwtService.generateToken(user);

            java.util.Set<String> roles = user.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));

            return new AuthResponse(
                    token,
                    "Bearer",
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    roles
            );
        } catch (DisabledException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Email is not verified");
        } catch (LockedException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User account is blocked");
        } catch (BadCredentialsException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }
    }

    @GetMapping("/verify-email")
    public VerificationResponse verifyEmail(@RequestParam String token) {
        AppUser user = emailVerificationService.confirmEmail(token);
        return new VerificationResponse("Email successfully confirmed", true, user.getUsername());
    }

    @PostMapping("/resend-verification")
    public MessageResponse resendVerification(@Valid @RequestBody ResendVerificationRequest req) {
        emailVerificationService.resendVerification(req.email());
        return new MessageResponse("Verification email sent");
    }

    @PostMapping("/forgot-password")
    public MessageResponse forgotPassword(@Valid @RequestBody ForgotPasswordRequest req) {
        passwordResetService.requestReset(req.email());
        return new MessageResponse("Password reset email sent");
    }

    @PostMapping("/reset-password")
    public MessageResponse resetPassword(@Valid @RequestBody ResetPasswordRequest req) {
        passwordResetService.resetPassword(req.token(), req.newPassword());
        return new MessageResponse("Password successfully updated");
    }
}