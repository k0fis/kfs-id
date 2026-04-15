package eu.kofis.id.resource;

import eu.kofis.id.entity.User;
import eu.kofis.id.entity.UserApp;
import eu.kofis.id.service.JwtService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import org.mindrot.jbcrypt.BCrypt;

@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    JwtService jwtService;

    @POST
    @Path("/login")
    public Response login(LoginRequest request) {
        if (request == null || request.username == null || request.password == null) {
            return Response.status(400).entity(Map.of("error", "Missing username or password")).build();
        }

        User user = User.findByUsername(request.username);
        if (user == null || !BCrypt.checkpw(request.password, user.password)) {
            return Response.status(401).entity(Map.of("error", "Invalid credentials")).build();
        }

        List<String> apps = UserApp.appNamesForUser(user);
        String token = jwtService.generateToken(user.username, apps);
        return Response.ok(Map.of(
                "token", token,
                "username", user.username,
                "apps", apps,
                "expiresIn", jwtService.getExpirySeconds()
        )).build();
    }

    @POST
    @Path("/setup")
    @Transactional
    public Response setup(LoginRequest request) {
        if (request == null || request.username == null || request.password == null) {
            return Response.status(400).entity(Map.of("error", "Missing username or password")).build();
        }

        if (User.count() > 0) {
            return Response.status(409).entity(Map.of("error", "User already exists")).build();
        }

        User user = new User();
        user.username = request.username;
        user.password = BCrypt.hashpw(request.password, BCrypt.gensalt());
        user.persist();

        for (String app : List.of("manga", "akcie")) {
            UserApp ua = new UserApp();
            ua.user = user;
            ua.app = app;
            ua.persist();
        }

        return Response.ok(Map.of("message", "User created", "username", user.username)).build();
    }

    @GET
    @Path("/verify")
    public Response verify(@HeaderParam("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Response.status(401).entity(Map.of("error", "Invalid or expired token")).build();
        }
        String token = authHeader.substring(7);
        String username = jwtService.validateToken(token);
        if (username == null) {
            return Response.status(401).entity(Map.of("error", "Invalid or expired token")).build();
        }
        List<String> apps = jwtService.extractApps(token);
        return Response.ok(Map.of("username", username, "apps", apps, "valid", true)).build();
    }

    public static class LoginRequest {
        public String username;
        public String password;
    }
}
