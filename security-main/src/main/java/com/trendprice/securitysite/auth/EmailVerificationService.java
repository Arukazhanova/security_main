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
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserService userService;
    private final MailService mailService;
    private final String baseUrl;

    public EmailVerificationService(
            EmailVerificationTokenRepository tokenRepository,
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
    public EmailVerificationToken createToken(AppUser user) {
        tokenRepository.deleteByUser(user);

        EmailVerificationToken token = new EmailVerificationToken(
                UUID.randomUUID().toString(),
                user,
                Instant.now(),
                Instant.now().plus(24, ChronoUnit.HOURS)
        );

        return tokenRepository.save(token);
    }

    @Transactional
    public void sendVerificationEmail(AppUser user) {
        EmailVerificationToken token = createToken(user);
        String verificationLink = baseUrl + "/verify-email?token=" + token.getToken();
        mailService.sendVerificationEmail(user.getEmail(), user.getUsername(), verificationLink);
    }

    @Transactional
    public void resendVerification(String email) {
        AppUser user = userService.findByEmail(email);

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is already verified");
        }

        sendVerificationEmail(user);
    }

    @Transactional
    public AppUser confirmEmail(String tokenValue) {
        EmailVerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Verification token not found"));

        // если уже подтверждено — просто считаем это успешным кейсом
        if (token.getConfirmedAt() != null) {
            return token.getUser();
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification token expired");
        }

        AppUser user = token.getUser();
        userService.enableUser(user);
        token.setConfirmedAt(Instant.now());
        tokenRepository.save(token);

        return user;
    }
}