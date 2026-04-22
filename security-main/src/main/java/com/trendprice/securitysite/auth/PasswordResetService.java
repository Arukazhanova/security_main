package com.trendprice.securitysite.auth;

import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserService userService;
    private final MailService mailService;
    private final String baseUrl;

    public PasswordResetService(
            PasswordResetTokenRepository tokenRepository,
            UserService userService,
            MailService mailService,
            @Value("${app.base-url}") String baseUrl
    ) {
        this.tokenRepository = tokenRepository;
        this.userService = userService;
        this.mailService = mailService;
        this.baseUrl = baseUrl;
    }

    @Transactional
    public void requestReset(String email) {
        AppUser user = userService.findByEmail(email);

        tokenRepository.deleteByUser(user);

        PasswordResetToken token = new PasswordResetToken(
                UUID.randomUUID().toString(),
                user,
                Instant.now(),
                Instant.now().plus(1, ChronoUnit.HOURS)
        );

        PasswordResetToken saved = tokenRepository.save(token);
        String resetLink = baseUrl + "/reset-password?token=" + saved.getToken();

        mailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), resetLink);
    }

    @Transactional
    public void resetPassword(String tokenValue, String newPassword) {
        PasswordResetToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Reset token not found"));

        if (token.getUsedAt() != null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reset token already used");
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reset token expired");
        }

        AppUser user = token.getUser();
        userService.updatePassword(user, newPassword);

        token.setUsedAt(Instant.now());
        tokenRepository.save(token);
    }
}