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
class UserResourceTest {

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

    @Test
    void listUsersRequiresAuth() {
        given()
        .when()
            .get("/users")
        .then()
            .statusCode(401);
    }

    @Test
    void listUsersReturnsAll() {
        String token = loginToken("admin", "pass");
        createUserWithApps("user2", "pass2", "manga");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/users")
        .then()
            .statusCode(200)
            .body("$", hasSize(2))
            .body("username", hasItems("admin", "user2"));
    }

    @Test
    void createUserSuccess() {
        String token = loginToken("admin", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"newuser\",\"password\":\"newpass\",\"apps\":[\"manga\",\"akcie\"]}")
        .when()
            .post("/users")
        .then()
            .statusCode(201)
            .body("username", is("newuser"))
            .body("apps", hasItems("manga", "akcie"));
    }

    @Test
    void createUserDuplicate() {
        String token = loginToken("admin", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"admin\",\"password\":\"other\"}")
        .when()
            .post("/users")
        .then()
            .statusCode(409);
    }

    @Test
    void createUserMissingFields() {
        String token = loginToken("admin", "pass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{}")
        .when()
            .post("/users")
        .then()
            .statusCode(400);
    }

    @Test
    void deleteUser() {
        String token = loginToken("admin", "pass");
        Long userId = createUserWithApps("todelete", "pass", "manga");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .delete("/users/" + userId)
        .then()
            .statusCode(204);

        // Verify user is gone
        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/users")
        .then()
            .body("$", hasSize(1));
    }

    @Test
    void deleteUserNotFound() {
        String token = loginToken("admin", "pass");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .delete("/users/9999")
        .then()
            .statusCode(404);
    }

    @Test
    void changePassword() {
        String token = loginToken("admin", "pass");
        Long userId = createUser("target", "oldpass");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"password\":\"newpass\"}")
        .when()
            .put("/users/" + userId + "/password")
        .then()
            .statusCode(200)
            .body("message", is("Password changed"));

        // Verify new password works
        given()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{\"username\":\"target\",\"password\":\"newpass\"}")
        .when()
            .post("/login")
        .then()
            .statusCode(200);
    }

    @Test
    void addAppToUser() {
        String token = loginToken("admin", "pass");
        Long userId = createUser("target", "pass2");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
        .when()
            .post("/users/" + userId + "/apps/manga")
        .then()
            .statusCode(201)
            .body("app", is("manga"));
    }

    @Test
    void addDuplicateApp() {
        String token = loginToken("admin", "pass");
        Long userId = createUserWithApps("target", "pass2", "manga");

        given()
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
        .when()
            .post("/users/" + userId + "/apps/manga")
        .then()
            .statusCode(409);
    }

    @Test
    void removeAppFromUser() {
        String token = loginToken("admin", "pass");
        Long userId = createUserWithApps("target", "pass2", "manga", "akcie");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .delete("/users/" + userId + "/apps/manga")
        .then()
            .statusCode(204);

        // Verify app is removed
        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/users")
        .then()
            .body("find { it.username == 'target' }.apps", hasSize(1));
    }

    @Test
    void removeAppNotAssigned() {
        String token = loginToken("admin", "pass");
        Long userId = createUser("target", "pass2");

        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .delete("/users/" + userId + "/apps/manga")
        .then()
            .statusCode(404);
    }

    @Transactional
    Long createUser(String username, String password) {
        User u = new User();
        u.username = username;
        u.password = BCrypt.hashpw(password, BCrypt.gensalt());
        u.persist();
        return u.id;
    }

    @Transactional
    Long createUserWithApps(String username, String password, String... apps) {
        User u = new User();
        u.username = username;
        u.password = BCrypt.hashpw(password, BCrypt.gensalt());
        u.persist();
        for (String app : apps) {
            UserApp ua = new UserApp();
            ua.user = u;
            ua.app = app;
            ua.persist();
        }
        return u.id;
    }
}
