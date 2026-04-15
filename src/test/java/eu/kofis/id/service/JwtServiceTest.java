package eu.kofis.id.service;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private JwtService createService(String secret, int expiryDays) {
        JwtService svc = new JwtService();
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
        String token = svc.generateToken("kofis", List.of("manga", "akcie"));
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);
        assertEquals("kofis", svc.validateToken(token));
    }

    @Test
    void generateTokenWithEmptyApps() {
        JwtService svc = createService("my-test-secret", 30);
        String token = svc.generateToken("kofis", List.of());
        assertEquals("kofis", svc.validateToken(token));
        assertEquals(List.of(), svc.extractApps(token));
    }

    @Test
    void extractAppsFromToken() {
        JwtService svc = createService("my-test-secret", 30);
        String token = svc.generateToken("kofis", List.of("manga", "akcie"));
        List<String> apps = svc.extractApps(token);
        assertEquals(List.of("manga", "akcie"), apps);
    }

    @Test
    void validateRejectsWrongSecret() {
        JwtService svc1 = createService("secret-one", 30);
        JwtService svc2 = createService("secret-two", 30);
        String token = svc1.generateToken("kofis", List.of());
        assertNull(svc2.validateToken(token));
    }

    @Test
    void validateRejectsExpiredToken() {
        JwtService svc = createService("my-test-secret", 30);
        long now = java.time.Instant.now().getEpochSecond();
        String token = svc.buildJwt("kofis", List.of("manga"), now - 100, now - 1);
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
        String token = svc.generateToken("kofis", List.of("manga"));
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
        assertEquals("kofis", JwtService.extractJsonField("{\"sub\":\"kofis\",\"apps\":[]}", "sub"));
        assertNull(JwtService.extractJsonField("{\"sub\":\"kofis\"}", "missing"));
    }

    @Test
    void extractJsonLongParsesCorrectly() {
        assertEquals(1713100000L, JwtService.extractJsonLong("{\"exp\":1713100000,\"iat\":100}", "exp"));
        assertEquals(100L, JwtService.extractJsonLong("{\"exp\":1713100000,\"iat\":100}", "iat"));
        assertEquals(0L, JwtService.extractJsonLong("{\"exp\":123}", "missing"));
    }

    @Test
    void extractJsonArrayParsesCorrectly() {
        assertEquals(List.of("manga", "akcie"), JwtService.extractJsonArray("{\"apps\":[\"manga\",\"akcie\"],\"iat\":1}", "apps"));
        assertEquals(List.of(), JwtService.extractJsonArray("{\"apps\":[],\"iat\":1}", "apps"));
        assertEquals(List.of(), JwtService.extractJsonArray("{\"iat\":1}", "apps"));
    }

    @Test
    void usernameWithDots() {
        JwtService svc = createService("my-test-secret", 30);
        String token = svc.generateToken("user.name", List.of("manga"));
        assertEquals("user.name", svc.validateToken(token));
    }

    @Test
    void extractAppsFromInvalidToken() {
        JwtService svc = createService("my-test-secret", 30);
        assertEquals(List.of(), svc.extractApps("garbage"));
    }
}
