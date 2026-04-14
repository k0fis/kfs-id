package eu.kofis.id.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService createService(String secret, int expiryDays) {
        JwtService svc = new JwtService();
        // Inject config values directly via field access
        try {
            var secretField = JwtService.class.getDeclaredField("secret");
            secretField.setAccessible(true);
            secretField.set(svc, secret);

            var expiryField = JwtService.class.getDeclaredField("expiryDays");
            expiryField.setAccessible(true);
            expiryField.set(svc, expiryDays);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return svc;
    }

    @Test
    void generateAndValidate() {
        JwtService svc = createService("my-test-secret", 30);
        String token = svc.generateToken("kofis");
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
        assertEquals("kofis", svc.validateToken(token));
    }

    @Test
    void validateRejectsWrongSecret() {
        JwtService svc1 = createService("secret-one", 30);
        JwtService svc2 = createService("secret-two", 30);
        String token = svc1.generateToken("kofis");
        assertNull(svc2.validateToken(token));
    }

    @Test
    void validateRejectsExpiredToken() {
        JwtService svc = createService("my-test-secret", 30);
        // Build a token that expired 1 second ago
        long now = java.time.Instant.now().getEpochSecond();
        String token = svc.buildJwt("kofis", now - 100, now - 1);
        assertNull(svc.validateToken(token));
    }

    @Test
    void validateRejectsMalformedToken() {
        JwtService svc = createService("my-test-secret", 30);
        assertNull(svc.validateToken("not.a.valid.token"));
        assertNull(svc.validateToken("garbage"));
        assertNull(svc.validateToken(""));
    }

    @Test
    void validateRejectsTamperedPayload() {
        JwtService svc = createService("my-test-secret", 30);
        String token = svc.generateToken("kofis");
        // Tamper with the payload
        String[] parts = token.split("\\.");
        String tampered = parts[0] + "." + parts[1] + "X" + "." + parts[2];
        assertNull(svc.validateToken(tampered));
    }

    @Test
    void expirySeconds() {
        JwtService svc = createService("s", 30);
        assertEquals(30 * 86400, svc.getExpirySeconds());
    }

    @Test
    void extractJsonFieldParsesCorrectly() {
        assertEquals("kofis", JwtService.extractJsonField("{\"sub\":\"kofis\",\"role\":\"user\"}", "sub"));
        assertEquals("user", JwtService.extractJsonField("{\"sub\":\"kofis\",\"role\":\"user\"}", "role"));
        assertNull(JwtService.extractJsonField("{\"sub\":\"kofis\"}", "missing"));
    }

    @Test
    void extractJsonLongParsesCorrectly() {
        assertEquals(1713100000L, JwtService.extractJsonLong("{\"exp\":1713100000,\"iat\":100}", "exp"));
        assertEquals(100L, JwtService.extractJsonLong("{\"exp\":1713100000,\"iat\":100}", "iat"));
        assertEquals(0L, JwtService.extractJsonLong("{\"exp\":123}", "missing"));
    }

    @Test
    void usernameWithDots() {
        JwtService svc = createService("my-test-secret", 30);
        String token = svc.generateToken("user.name");
        assertEquals("user.name", svc.validateToken(token));
    }
}
