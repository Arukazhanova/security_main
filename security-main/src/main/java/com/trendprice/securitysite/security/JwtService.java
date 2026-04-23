package com.trendprice.securitysite.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trendprice.securitysite.user.AppUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class JwtService {

    private final String secret;
    private final long expirationMs;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expirationMs
    ) {
        this.secret = secret;
        this.expirationMs = expirationMs;
    }

    public String generateToken(AppUser user) {
        try {
            long nowSec = Instant.now().getEpochSecond();
            long expSec = Instant.now().plusMillis(expirationMs).getEpochSecond();

            Map<String, Object> header = Map.of(
                    "alg", "HS256",
                    "typ", "JWT"
            );

            List<String> roles = user.getAuthorities().stream()
                    .map(authority -> authority.getAuthority())
                    .toList();

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("sub", user.getUsername());
            payload.put("uid", user.getId());
            payload.put("email", user.getEmail());
            payload.put("roles", roles);
            payload.put("iss", "securitysite");
            payload.put("tokenType", "access");
            payload.put("iat", nowSec);
            payload.put("exp", expSec);

            String headerJson = objectMapper.writeValueAsString(header);
            String payloadJson = objectMapper.writeValueAsString(payload);

            String encodedHeader = base64Url(headerJson.getBytes(StandardCharsets.UTF_8));
            String encodedPayload = base64Url(payloadJson.getBytes(StandardCharsets.UTF_8));

            String data = encodedHeader + "." + encodedPayload;
            String signature = hmacSha256Base64Url(data, secret);

            return data + "." + signature;
        } catch (Exception e) {
            throw new IllegalStateException("JWT generation failed: " + e.getMessage(), e);
        }
    }

    public boolean isTokenValid(String token) {
        parseAndValidate(token);
        return true;
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        Map<String, Object> claims = parseAndValidate(token);
        String username = (String) claims.get("sub");

        return userDetails != null
                && userDetails.isEnabled()
                && username != null
                && username.equals(userDetails.getUsername());
    }

    public String extractUsername(String token) {
        Map<String, Object> claims = parseAndValidate(token);
        Object sub = claims.get("sub");
        if (sub == null) {
            throw new RuntimeException("Missing claim: sub");
        }
        return sub.toString();
    }

    public List<String> extractRoles(String token) {
        Map<String, Object> claims = parseAndValidate(token);
        Object roles = claims.get("roles");

        if (roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }

        return List.of();
    }

    public Long extractUserId(String token) {
        Map<String, Object> claims = parseAndValidate(token);
        Object uid = claims.get("uid");

        if (uid instanceof Integer i) return i.longValue();
        if (uid instanceof Long l) return l;
        if (uid instanceof String s) return Long.parseLong(s);

        return null;
    }

    public String extractEmail(String token) {
        Map<String, Object> claims = parseAndValidate(token);
        Object email = claims.get("email");
        return email == null ? null : email.toString();
    }

    private Map<String, Object> parseAndValidate(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new RuntimeException("Invalid token format");
            }

            String data = parts[0] + "." + parts[1];
            String expectedSig = hmacSha256Base64Url(data, secret);

            if (!constantTimeEquals(expectedSig, parts[2])) {
                throw new RuntimeException("Bad signature");
            }

            String payloadJson = new String(
                    Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8
            );

            Map<String, Object> claims = objectMapper.readValue(
                    payloadJson,
                    new TypeReference<>() {}
            );

            Object expObj = claims.get("exp");
            if (expObj == null) {
                throw new RuntimeException("Missing claim: exp");
            }

            long exp = ((Number) expObj).longValue();
            long now = Instant.now().getEpochSecond();

            if (now >= exp) {
                throw new RuntimeException("Token expired");
            }

            return claims;
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWT: " + e.getMessage(), e);
        }
    }

    private String hmacSha256Base64Url(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"
            );
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
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }

        int res = 0;
        for (int i = 0; i < a.length(); i++) {
            res |= a.charAt(i) ^ b.charAt(i);
        }
        return res == 0;
    }
}