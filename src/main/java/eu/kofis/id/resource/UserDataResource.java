package eu.kofis.id.resource;

import eu.kofis.id.entity.User;
import eu.kofis.id.entity.UserData;
import eu.kofis.id.service.JwtService;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Path("/data")
public class UserDataResource {

    private static final int MAX_SIZE = 512 * 1024;

    @Inject
    JwtService jwtService;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response listApps(@HeaderParam("Authorization") String authHeader) {
        User user = authenticate(authHeader);
        if (user == null) return unauthorized();
        List<String> apps = UserData.appsForUser(user);
        return Response.ok(apps).build();
    }

    @GET
    @Path("/{app}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listKeys(@HeaderParam("Authorization") String authHeader, @PathParam("app") String app) {
        User user = authenticate(authHeader);
        if (user == null) return unauthorized();
        List<String> keys = UserData.keysForUserAndApp(user, app);
        return Response.ok(keys).build();
    }

    @GET
    @Path("/{app}/{key}")
    public Response getValue(@HeaderParam("Authorization") String authHeader,
                             @PathParam("app") String app, @PathParam("key") String key) {
        User user = authenticate(authHeader);
        if (user == null) return unauthorized();
        UserData ud = UserData.findByUserAppKey(user, app, key);
        if (ud == null) return Response.status(404).entity(Map.of("error", "Not found")).type(MediaType.APPLICATION_JSON).build();
        return Response.ok(ud.data).type(ud.contentType).build();
    }

    @PUT
    @Path("/{app}/{key}")
    @Transactional
    public Response putValue(@HeaderParam("Authorization") String authHeader,
                             @Context HttpHeaders headers,
                             @PathParam("app") String app, @PathParam("key") String key,
                             String body) {
        User user = authenticate(authHeader);
        if (user == null) return unauthorized();
        if (body == null || body.isEmpty()) {
            return Response.status(400).entity(Map.of("error", "Empty body")).type(MediaType.APPLICATION_JSON).build();
        }
        if (body.length() > MAX_SIZE) {
            return Response.status(413).entity(Map.of("error", "Payload too large")).type(MediaType.APPLICATION_JSON).build();
        }
        String contentType = headers.getHeaderString("Content-Type");
        if (contentType == null) contentType = "application/json";

        UserData ud = UserData.findByUserAppKey(user, app, key);
        if (ud != null) {
            ud.data = body;
            ud.contentType = contentType;
            ud.updatedAt = Instant.now();
        } else {
            ud = new UserData();
            ud.user = user;
            ud.app = app;
            ud.dataKey = key;
            ud.data = body;
            ud.contentType = contentType;
            ud.persist();
        }
        return Response.ok(Map.of("ok", true)).type(MediaType.APPLICATION_JSON).build();
    }

    @DELETE
    @Path("/{app}/{key}")
    @Transactional
    public Response deleteValue(@HeaderParam("Authorization") String authHeader,
                                @PathParam("app") String app, @PathParam("key") String key) {
        User user = authenticate(authHeader);
        if (user == null) return unauthorized();
        UserData ud = UserData.findByUserAppKey(user, app, key);
        if (ud == null) return Response.status(404).entity(Map.of("error", "Not found")).type(MediaType.APPLICATION_JSON).build();
        ud.delete();
        return Response.noContent().build();
    }

    private User authenticate(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return null;
        String username = jwtService.validateToken(authHeader.substring(7));
        if (username == null) return null;
        return User.findByUsername(username);
    }

    private Response unauthorized() {
        return Response.status(401).entity(Map.of("error", "Unauthorized")).type(MediaType.APPLICATION_JSON).build();
    }
}
