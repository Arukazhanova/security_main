package com.trendprice.securitysite.dto.auth;

import com.trendprice.securitysite.auth.LocalMailMessage;

import java.time.Instant;

public record LocalMailMessageResponse(
        Long id,
        String recipient,
        String subject,
        String body,
        Instant createdAt
) {
    public static LocalMailMessageResponse from(LocalMailMessage message) {
        return new LocalMailMessageResponse(
                message.getId(),
                message.getRecipient(),
                message.getSubject(),
                message.getBody(),
                message.getCreatedAt()
        );
    }
}