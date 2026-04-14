package eu.kofis.id.service;

import jakarta.enterprise.context.ApplicationScoped;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class JwtService {

    private static final String ALGORITHM = "HmacSHA256";

    @ConfigProperty(name = "kfs.id.jwt.secret")
    String secret;

    @ConfigProperty(name = "kfs.id.jwt.expiry-days", defaultValue = "30")
    int expiryDays;

    public String generateToken(String username) {
        long now = Instant.now().getEpochSecond();
        long exp = now + (long) expiryDays * 86400;
        return buildJwt(username, now, exp);
    }

    public String validateToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;

        String headerPayload = parts[0] + "." + parts[1];
        String expectedSig = hmacSign(headerPayload);
        if (!constantTimeEquals(parts[2], expectedSig)) return null;

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String sub = extractJsonField(payload, "sub");
        long exp = extractJsonLong(payload, "exp");

        if (exp < Instant.now().getEpochSecond()) return null;
        return sub;
    }

    public long getExpirySeconds() {
        return (long) expiryDays * 86400;
    }

    String buildJwt(String subject, long iat, long exp) {
        String header = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"" + escapeJson(subject) + "\",\"role\":\"user\",\"iat\":" + iat + ",\"exp\":" + exp + "}");
        String signature = hmacSign(header + "." + payload);
        return header + "." + payload + "." + signature;
    }

    String hmacSign(String data) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    private static String base64Url(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static String extractJsonField(String json, String field) {
        String key = "\"" + field + "\":\"";
        int start = json.indexOf(key);
        if (start < 0) return null;
        start += key.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    static long extractJsonLong(String json, String field) {
        String key = "\"" + field + "\":";
        int start = json.indexOf(key);
        if (start < 0) return 0;
        start += key.length();
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        if (end == start) return 0;
        return Long.parseLong(json.substring(start, end));
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
