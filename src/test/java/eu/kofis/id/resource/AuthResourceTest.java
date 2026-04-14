package eu.kofis.id.resource;

import eu.kofis.id.entity.User;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.core.MediaType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

@QuarkusTest
class AuthResourceTest {

    @BeforeEach
    @Transactional
    void cleanup() {
        User.deleteAll();
    }

    @Test
    void setupCreatesFirstUser() {
        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"kofis\",\"password\":\"test123\"}")
        .when()
            .post("/setup")
        .then()
            .statusCode(200)
            .body("message", is("User created"))
            .body("username", is("kofis"));
    }

    @Test
    void setupRejectsSecondUser() {
        createUser("kofis", "test123");

        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"another\",\"password\":\"pass\"}")
        .when()
            .post("/setup")
        .then()
            .statusCode(409)
            .body("error", is("User already exists"));
    }

    @Test
    void loginSuccess() {
        createUser("kofis", "test123");

        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"kofis\",\"password\":\"test123\"}")
        .when()
            .post("/login")
        .then()
            .statusCode(200)
            .body("token", notNullValue())
            .body("username", is("kofis"))
            .body("expiresIn", notNullValue());
    }

    @Test
    void loginWrongPassword() {
        createUser("kofis", "test123");

        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"kofis\",\"password\":\"wrong\"}")
        .when()
            .post("/login")
        .then()
            .statusCode(401)
            .body("error", is("Invalid credentials"));
    }

    @Test
    void loginUnknownUser() {
        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"nobody\",\"password\":\"test\"}")
        .when()
            .post("/login")
        .then()
            .statusCode(401)
            .body("error", is("Invalid credentials"));
    }

    @Test
    void loginMissingFields() {
        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{}")
        .when()
            .post("/login")
        .then()
            .statusCode(400);
    }

    @Test
    void verifyValidToken() {
        createUser("kofis", "test123");

        String token = given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"kofis\",\"password\":\"test123\"}")
        .when()
            .post("/login")
        .then()
            .extract().path("token");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/verify")
        .then()
            .statusCode(200)
            .body("username", is("kofis"))
            .body("valid", is(true));
    }

    @Test
    void verifyNoToken() {
        given()
        .when()
            .get("/verify")
        .then()
            .statusCode(401);
    }

    @Test
    void verifyInvalidToken() {
        given()
            .header("Authorization", "Bearer garbage.token.here")
        .when()
            .get("/verify")
        .then()
            .statusCode(401);
    }

    @Transactional
    void createUser(String username, String password) {
        User u = new User();
        u.username = username;
        u.password = BCrypt.hashpw(password, BCrypt.gensalt());
        u.persist();
    }
}
