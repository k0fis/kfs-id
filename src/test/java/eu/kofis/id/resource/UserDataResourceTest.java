package eu.kofis.id.resource;

import eu.kofis.id.entity.User;
import eu.kofis.id.entity.UserApp;
import eu.kofis.id.entity.UserData;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.core.MediaType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;

@QuarkusTest
class UserDataResourceTest {

    @BeforeEach
    @Transactional
    void cleanup() {
        UserData.deleteAll();
        UserApp.deleteAll();
        User.deleteAll();
    }

    private String loginToken(String username, String password) {
        createUser(username, password);
        return given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}")
        .when()
            .post("/login")
        .then()
            .extract().path("token");
    }

    // --- PUT + GET roundtrip ---

    @Test
    void putAndGetJson() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"page\":42}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(200)
            .body("ok", is(true));

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/books/progress")
        .then()
            .statusCode(200)
            .contentType(MediaType.APPLICATION_JSON)
            .body("page", is(42));
    }

    @Test
    void putOverwrite() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"v\":1}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"v\":2}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/books/progress")
        .then()
            .statusCode(200)
            .body("v", is(2));
    }

    // --- GET 404 ---

    @Test
    void getMissingKey() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/books/nonexistent")
        .then()
            .statusCode(404);
    }

    // --- DELETE ---

    @Test
    void deleteKey() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"x\":1}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .delete("/data/books/progress")
        .then()
            .statusCode(204);

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/books/progress")
        .then()
            .statusCode(404);
    }

    @Test
    void deleteMissingKey() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .delete("/data/books/nonexistent")
        .then()
            .statusCode(404);
    }

    // --- List keys and apps ---

    @Test
    void listKeys() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"a\":1}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"b\":2}")
        .when()
            .put("/data/books/favorites")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/books")
        .then()
            .statusCode(200)
            .body("$", hasSize(2))
            .body("$", hasItems("progress", "favorites"));
    }

    @Test
    void listApps() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{}")
        .when()
            .put("/data/kap/queue")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data")
        .then()
            .statusCode(200)
            .body("$", hasSize(2))
            .body("$", hasItems("books", "kap"));
    }

    @Test
    void listKeysEmpty() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/books")
        .then()
            .statusCode(200)
            .body("$", hasSize(0));
    }

    @Test
    void listAppsEmpty() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data")
        .then()
            .statusCode(200)
            .body("$", hasSize(0));
    }

    // --- Auth required ---

    @Test
    void unauthorizedGetApps() {
        given()
        .when()
            .get("/data")
        .then()
            .statusCode(401);
    }

    @Test
    void unauthorizedPut() {
        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"x\":1}")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(401);
    }

    @Test
    void unauthorizedDelete() {
        given()
        .when()
            .delete("/data/books/progress")
        .then()
            .statusCode(401);
    }

    // --- Size limit ---

    @Test
    void payloadTooLarge() {
        String token = loginToken("kofis", "pass");
        String bigBody = "x".repeat(512 * 1024 + 1);

        given()
            .header("Authorization", "Bearer " + token)
            .contentType("text/plain")
            .body(bigBody)
        .when()
            .put("/data/books/huge")
        .then()
            .statusCode(413);
    }

    // --- Content-Type preserved ---

    @Test
    void xmlContentTypePreserved() {
        String token = loginToken("kofis", "pass");
        String opml = "<opml version=\"2.0\"><head><title>test</title></head><body/></opml>";

        given()
            .header("Authorization", "Bearer " + token)
            .contentType("text/xml")
            .body(opml)
        .when()
            .put("/data/kap/feeds")
        .then()
            .statusCode(200);

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/data/kap/feeds")
        .then()
            .statusCode(200)
            .contentType("text/xml")
            .body(containsString("<opml"));
    }

    // --- Empty body ---

    @Test
    void putEmptyBody() {
        String token = loginToken("kofis", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("")
        .when()
            .put("/data/books/progress")
        .then()
            .statusCode(400);
    }

    @Transactional
    void createUser(String username, String password) {
        User u = new User();
        u.username = username;
        u.password = BCrypt.hashpw(password, BCrypt.gensalt());
        u.persist();
    }
}
