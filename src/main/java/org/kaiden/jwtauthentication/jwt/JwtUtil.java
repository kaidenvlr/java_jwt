package org.kaiden.jwtauthentication.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

public class JwtUtil {
    private static final String SECRET = "super_long_secret_change_me_at_runtime_32+chars";

    // Utilities for JWT validation and generation
    // Simple Parsers
    private static Long extractExpire(String json) {
        int i = json.indexOf("\"exp\":");
        if (i < 0) return null;
        i += "\"exp\":".length();
        int j = i;
        while (j < json.length() && Character.isDigit(json.charAt(j))) j++;
        return Long.parseLong(json.substring(i, j));
    }

    private static String extractSubject(String json) {
        int i = json.indexOf("\"sub\":\"");
        if (i < 0) return null;
        i += "\"sub\":\"".length();
        int j = json.indexOf('"', i);
        return json.substring(i, j);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String b64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sign(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return b64Url(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean constantTimeEquality(String a, String b) {
        if (a.length() != b.length()) return false;
        int r = 0;
        for (int i = 0; i < a.length(); i++) r |= a.charAt(i) ^ b.charAt(i);
        return r == 0;
    }

    // main methods
    public static String generate(String subject, long ttlSeconds, Map<String, Object> claims) {
        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        long now = Instant.now().getEpochSecond();
        StringBuilder payload = new StringBuilder("{")
                .append("\"sub\":\"").append(escape(subject)).append("\",")
                .append("\"iat\":").append(now).append(",")
                .append("\"exp\":").append(now + ttlSeconds);

        if (claims != null) {
            for (var e : claims.entrySet()) {
                payload.append(",\"").append(escape(e.getKey())).append("\":");
                Object v = e.getValue();
                if (v instanceof Number || v instanceof Boolean) {
                    payload.append(v);
                } else {
                    payload.append("\"").append(escape(String.valueOf(v))).append("\"");
                }
            }
        }
        payload.append("}");

        String header = b64Url(headerJson.getBytes(StandardCharsets.UTF_8));
        String body = b64Url(payload.toString().getBytes(StandardCharsets.UTF_8));
        String signature = sign(header + "." + body);
        return header + "." + body + "." + signature;
    }

    public static String validateAndGetSub(String token) {
        // check for token validity
        String[] parts = token.split("\\.");
        if (parts.length != 3) throw new IllegalArgumentException("Invalid token");

        // check for signature validity by time
        String header = parts[0], body = parts[1], signature = parts[2];
        String expected = sign(header + "." + body);
        if (!constantTimeEquality(expected, signature)) throw new IllegalArgumentException("Invalid signature");

        String json = new String(Base64.getUrlDecoder().decode(body), StandardCharsets.UTF_8);
        long now = Instant.now().getEpochSecond();
        Long exp = extractExpire(json);
        if (exp == null || now >= exp) throw new IllegalArgumentException("Token expired");
        return extractSubject(json);
    }
}
