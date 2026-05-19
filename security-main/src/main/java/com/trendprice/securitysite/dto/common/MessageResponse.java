package com.trendprice.securitysite.dto.common;

public record MessageResponse(
        String message,
        String link,
        String token
) {
    public MessageResponse(String message) {
        this(message, null, null);
    }
}