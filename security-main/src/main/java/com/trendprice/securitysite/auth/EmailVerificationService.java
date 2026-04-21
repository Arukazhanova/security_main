package com.trendprice.securitysite.auth;

import com.trendprice.securitysite.user.AppUser;
import com.trendprice.securitysite.user.UserService;
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

    public EmailVerificationService(EmailVerificationTokenRepository tokenRepository, UserService userService) {
        this.tokenRepository = tokenRepository;
        this.userService = userService;
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

        EmailVerificationToken savedToken = tokenRepository.save(token);
        System.out.println("EMAIL VERIFICATION TOKEN for " + user.getUsername() + ": " + savedToken.getToken());
        return savedToken;
    }

    @Transactional
    public AppUser confirmEmail(String tokenValue) {
        EmailVerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Verification token not found"));

        if (token.getConfirmedAt() != null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already confirmed");
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