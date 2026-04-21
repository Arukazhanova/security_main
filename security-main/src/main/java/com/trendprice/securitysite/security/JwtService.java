package com.trendprice.securitysite.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

@Service
public class JwtService {

    private final String secret;
    private final long expirationMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expirationMs
    ) {
        this.secret = secret;
        this.expirationMs = expirationMs;
    }

    public String generateToken(String username) {
        long nowSec = Instant.now().getEpochSecond();
        long expSec = Instant.now().plusMillis(expirationMs).getEpochSecond();

        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson =
                "{\"sub\":\"" + escape(username) + "\",\"iat\":" + nowSec + ",\"exp\":" + expSec + "}";

        String header = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));
        String data = header + "." + payload;

        String signature = hmacSha256Base64Url(data, secret);
        return data + "." + signature;
    }

    public boolean isTokenValid(String token) {
        parseAndValidate(token);
        return true;
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        String payloadJson = parseAndValidate(token);
        String username = extractString(payloadJson, "sub");
        return userDetails != null
                && userDetails.isEnabled()
                && username.equals(userDetails.getUsername());
    }

    public String extractUsername(String token) {
        String payloadJson = parseAndValidate(token);
        return extractString(payloadJson, "sub");
    }

    private String parseAndValidate(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new RuntimeException("Invalid token format");

            String data = parts[0] + "." + parts[1];
            String expectedSig = hmacSha256Base64Url(data, secret);

            if (!constantTimeEquals(expectedSig, parts[2])) {
                throw new RuntimeException("Bad signature");
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

            long exp = extractLong(payloadJson, "exp");
            long now = Instant.now().getEpochSecond();
            if (now >= exp) throw new RuntimeException("Token expired");

            return payloadJson;
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWT: " + e.getMessage());
        }
    }

    private String hmacSha256Base64Url(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return base64Url(sig);
        } catch (Exception e) {
            throw new IllegalStateException("JWT signing failed: " + e.getMessage(), e);
        }
    }

    private String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int res = 0;
        for (int i = 0; i < a.length(); i++) res |= a.charAt(i) ^ b.charAt(i);
        return res == 0;
    }

    private String extractString(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start < 0) throw new RuntimeException("Missing claim: " + key);
        start += pattern.length();
        int end = json.indexOf("\"", start);
        if (end < 0) throw new RuntimeException("Bad JSON for claim: " + key);
        return json.substring(start, end);
    }

    private long extractLong(String json, String key) {
        String pattern = "\"" + key + "\":";
        int start = json.indexOf(pattern);
        if (start < 0) throw new RuntimeException("Missing claim: " + key);
        start += pattern.length();

        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;

        if (end == start) throw new RuntimeException("Bad number for claim: " + key);
        return Long.parseLong(json.substring(start, end));
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}