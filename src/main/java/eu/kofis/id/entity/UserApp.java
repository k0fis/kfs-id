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
@Table(name = "user_apps", uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "app"}))
public class UserApp extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    public User user;

    @Column(nullable = false, length = 64)
    public String app;

    @Column(name = "created_at", nullable = false)
    public Instant createdAt = Instant.now();

    public static List<UserApp> findByUser(User user) {
        return find("user", user).list();
    }

    public static List<String> appNamesForUser(User user) {
        return findByUser(user).stream().map(ua -> ua.app).toList();
    }

    public static UserApp findByUserAndApp(User user, String app) {
        return find("user = ?1 AND app = ?2", user, app).firstResult();
    }
}
