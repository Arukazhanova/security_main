package com.trendprice.securitysite.auth;

import com.trendprice.securitysite.dto.auth.AuthResponse;
import com.trendprice.securitysite.dto.auth.ForgotPasswordRequest;
import com.trendprice.securitysite.dto.auth.LoginRequest;
import com.trendprice.securitysite.dto.auth.RefreshTokenRequest;
import com.trendprice.securitysite.dto.auth.RegisterRequest;
import com.trendprice.securitysite.dto.auth.RegisterResponse;
import com.trendprice.securitysite.dto.auth.ResendVerificationRequest;
import com.trendprice.securitysite.dto.auth.ResetPasswordRequest;
import com.trendprice.securitysite.dto.auth.TokenRefreshResponse;
import com.trendprice.securitysite.dto.auth.VerificationResponse;
import com.trendprice.securitysite.dto.common.MessageResponse;
import com.trendprice.securitysite.security.JwtService;
import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final EmailVerificationService emailVerificationService;
    private final PasswordResetService passwordResetService;
    private final RefreshTokenService refreshTokenService;
    private final boolean exposeAuthLinksInResponse;

    public AuthController(
            UserService userService,
            JwtService jwtService,
            AuthenticationManager authManager,
            EmailVerificationService emailVerificationService,
            PasswordResetService passwordResetService,
            RefreshTokenService refreshTokenService,
            @Value("${app.auth.expose-links-in-response:true}") boolean exposeAuthLinksInResponse
    ) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authManager = authManager;
        this.emailVerificationService = emailVerificationService;
        this.passwordResetService = passwordResetService;
        this.refreshTokenService = refreshTokenService;
        this.exposeAuthLinksInResponse = exposeAuthLinksInResponse;
    }

    @PostMapping("/register")
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        AppUser user = userService.register(
                request.username(),
                request.password(),
                request.email()
        );

        EmailVerificationService.EmailDeliveryResult delivery =
                emailVerificationService.sendVerificationEmail(user);

        return new RegisterResponse(
                "Registration successful. Verification message saved to the local mailbox.",
                exposeAuthLinksInResponse ? delivery.link() : null,
                exposeAuthLinksInResponse ? delivery.token() : null
        );
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        AppUser user = (AppUser) authentication.getPrincipal();

        String accessToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);

        Set<String> roles = user.getAuthorities().stream()
                .map(authority -> authority.getAuthority().replace("ROLE_", ""))
                .collect(Collectors.toCollection(LinkedHashSet::new));

        return new AuthResponse(
                accessToken,
                refreshToken,
                "Bearer",
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                roles
        );
    }

    @GetMapping("/verify-email")
    public VerificationResponse verifyEmail(@RequestParam String token) {
        AppUser user = emailVerificationService.confirmEmail(token);

        return new VerificationResponse(
                "Email successfully confirmed",
                true,
                user.getUsername()
        );
    }

    @PostMapping("/resend-verification")
    public MessageResponse resendVerification(
            @Valid @RequestBody ResendVerificationRequest request
    ) {
        EmailVerificationService.EmailDeliveryResult delivery =
                emailVerificationService.resendVerification(request.email());

        return new MessageResponse(
                "Verification message saved to the local mailbox",
                exposeAuthLinksInResponse ? delivery.link() : null,
                exposeAuthLinksInResponse ? delivery.token() : null
        );
    }

    @PostMapping("/forgot-password")
    public MessageResponse forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest request
    ) {
        return passwordResetService.requestReset(request.email())
                .map(delivery -> new MessageResponse(
                        "Password reset message saved to the local mailbox",
                        exposeAuthLinksInResponse ? delivery.link() : null,
                        exposeAuthLinksInResponse ? delivery.token() : null
                ))
                .orElseGet(() -> new MessageResponse(
                        "If an account with this email exists, password reset instructions have been saved."
                ));
    }

    @PostMapping("/reset-password")
    public MessageResponse resetPassword(
            @Valid @RequestBody ResetPasswordRequest request
    ) {
        passwordResetService.resetPassword(
                request.token(),
                request.newPassword()
        );

        return new MessageResponse("Password successfully updated");
    }

    @PostMapping("/refresh")
    public TokenRefreshResponse refreshToken(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        String newAccessToken = refreshTokenService.refreshAccessToken(request.refreshToken());

        return new TokenRefreshResponse(
                newAccessToken,
                "Bearer"
        );
    }

    @PostMapping("/logout")
    public MessageResponse logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        refreshTokenService.logout(request.refreshToken());

        return new MessageResponse("Logged out successfully");
    }
}