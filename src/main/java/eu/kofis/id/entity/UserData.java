package eu.kofis.id.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "user_data", uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "app", "data_key"}))
public class UserData extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    public User user;

    @Column(nullable = false, length = 64)
    public String app;

    @Column(name = "data_key", nullable = false, length = 128)
    public String dataKey;

    @Column(nullable = false, columnDefinition = "TEXT")
    public String data;

    @Column(name = "content_type", nullable = false, length = 128)
    public String contentType = "application/json";

    @Column(name = "updated_at", nullable = false)
    public Instant updatedAt = Instant.now();

    @Column(name = "created_at", nullable = false)
    public Instant createdAt = Instant.now();

    public static UserData findByUserAppKey(User user, String app, String dataKey) {
        return find("user = ?1 AND app = ?2 AND dataKey = ?3", user, app, dataKey).firstResult();
    }

    public static List<UserData> findByUserAndApp(User user, String app) {
        return find("user = ?1 AND app = ?2", user, app).list();
    }

    public static List<String> keysForUserAndApp(User user, String app) {
        return findByUserAndApp(user, app).stream().map(ud -> ud.dataKey).toList();
    }

    public static List<String> appsForUser(User user) {
        return find("user", user).stream()
                .map(ud -> ((UserData) ud).app)
                .distinct()
                .sorted()
                .toList();
    }
}
