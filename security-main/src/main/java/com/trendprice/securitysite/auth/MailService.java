package com.trendprice.securitysite.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class MailService {

    private final JavaMailSender mailSender;
    private final String from;

    public MailService(JavaMailSender mailSender,
                       @Value("${spring.mail.username}") String from) {
        this.mailSender = mailSender;
        this.from = from;
    }

    public void sendVerificationEmail(String to, String username, String verificationLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("Confirm your email");
        message.setText(
                "Hi, " + username + "!\n\n" +
                        "Please confirm your email by clicking the link below:\n" +
                        verificationLink + "\n\n" +
                        "If you did not register, just ignore this email."
        );
        mailSender.send(message);
    }

    public void sendPasswordResetEmail(String to, String username, String resetLink) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("Reset your password");
        message.setText(
                "Hi, " + username + "!\n\n" +
                        "Use this link to reset your password:\n" +
                        resetLink + "\n\n" +
                        "If you did not request a password reset, just ignore this email."
        );
        mailSender.send(message);
    }
}