package eu.kofis.id.resource;

import eu.kofis.id.entity.User;
import eu.kofis.id.entity.UserApp;
import eu.kofis.id.service.JwtService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Map;
import org.mindrot.jbcrypt.BCrypt;

@Path("/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {

    @Inject
    JwtService jwtService;

    @GET
    public Response listUsers(@HeaderParam("Authorization") String authHeader) {
        if (!isAuthenticated(authHeader)) {
            return Response.status(401).entity(Map.of("error", "Unauthorized")).build();
        }
        List<Map<String, Object>> users = User.<User>listAll().stream().map(u -> Map.<String, Object>of(
                "id", u.id,
                "username", u.username,
                "apps", UserApp.appNamesForUser(u),
                "createdAt", u.createdAt.toString()
        )).toList();
        return Response.ok(users).build();
    }

    @POST
    @Transactional
    public Response createUser(@HeaderParam("Authorization") String authHeader, CreateUserRequest request) {
        if (!isAuthenticated(authHeader)) {
            return Response.status(401).entity(Map.of("error", "Unauthorized")).build();
        }
        if (request == null || request.username == null || request.password == null) {
            return Response.status(400).entity(Map.of("error", "Missing username or password")).build();
        }
        if (User.findByUsername(request.username) != null) {
            return Response.status(409).entity(Map.of("error", "User already exists")).build();
        }

        User user = new User();
        user.username = request.username;
        user.password = BCrypt.hashpw(request.password, BCrypt.gensalt());
        user.persist();

        if (request.apps != null) {
            for (String app : request.apps) {
                UserApp ua = new UserApp();
                ua.user = user;
                ua.app = app;
                ua.persist();
            }
        }

        return Response.status(201).entity(Map.of(
                "id", user.id,
                "username", user.username,
                "apps", request.apps != null ? request.apps : List.of()
        )).build();
    }

    @DELETE
    @Path("/{id}")
    @Transactional
    public Response deleteUser(@HeaderParam("Authorization") String authHeader, @PathParam("id") Long id) {
        if (!isAuthenticated(authHeader)) {
            return Response.status(401).entity(Map.of("error", "Unauthorized")).build();
        }
        User user = User.findById(id);
        if (user == null) {
            return Response.status(404).entity(Map.of("error", "User not found")).build();
        }
        UserApp.delete("user", user);
        user.delete();
        return Response.noContent().build();
    }

    @PUT
    @Path("/{id}/password")
    @Transactional
    public Response changePassword(@HeaderParam("Authorization") String authHeader, @PathParam("id") Long id, PasswordRequest request) {
        if (!isAuthenticated(authHeader)) {
            return Response.status(401).entity(Map.of("error", "Unauthorized")).build();
        }
        if (request == null || request.password == null) {
            return Response.status(400).entity(Map.of("error", "Missing password")).build();
        }
        User user = User.findById(id);
        if (user == null) {
            return Response.status(404).entity(Map.of("error", "User not found")).build();
        }
        user.password = BCrypt.hashpw(request.password, BCrypt.gensalt());
        return Response.ok(Map.of("message", "Password changed")).build();
    }

    @POST
    @Path("/{id}/apps/{app}")
    @Transactional
    public Response addApp(@HeaderParam("Authorization") String authHeader, @PathParam("id") Long id, @PathParam("app") String app) {
        if (!isAuthenticated(authHeader)) {
            return Response.status(401).entity(Map.of("error", "Unauthorized")).build();
        }
        User user = User.findById(id);
        if (user == null) {
            return Response.status(404).entity(Map.of("error", "User not found")).build();
        }
        if (UserApp.findByUserAndApp(user, app) != null) {
            return Response.status(409).entity(Map.of("error", "App already assigned")).build();
        }
        UserApp ua = new UserApp();
        ua.user = user;
        ua.app = app;
        ua.persist();
        return Response.status(201).entity(Map.of("app", app, "userId", user.id)).build();
    }

    @DELETE
    @Path("/{id}/apps/{app}")
    @Transactional
    public Response removeApp(@HeaderParam("Authorization") String authHeader, @PathParam("id") Long id, @PathParam("app") String app) {
        if (!isAuthenticated(authHeader)) {
            return Response.status(401).entity(Map.of("error", "Unauthorized")).build();
        }
        User user = User.findById(id);
        if (user == null) {
            return Response.status(404).entity(Map.of("error", "User not found")).build();
        }
        UserApp ua = UserApp.findByUserAndApp(user, app);
        if (ua == null) {
            return Response.status(404).entity(Map.of("error", "App not assigned")).build();
        }
        ua.delete();
        return Response.noContent().build();
    }

    private boolean isAuthenticated(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return false;
        return jwtService.validateToken(authHeader.substring(7)) != null;
    }

    public static class CreateUserRequest {
        public String username;
        public String password;
        public List<String> apps;
    }

    public static class PasswordRequest {
        public String password;
    }
}
