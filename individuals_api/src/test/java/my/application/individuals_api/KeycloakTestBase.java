package my.application.individuals_api;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.MountableFile;

public abstract class KeycloakTestBase {

    @Container
    static final GenericContainer<?> KEYCLOAK_CONTAINER;

    static {
        //noinspection resource
        KEYCLOAK_CONTAINER = new GenericContainer<>("quay.io/keycloak/keycloak:26.2")
                .withExposedPorts(8080)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withCommand("start-dev --import-realm")
                .withCopyFileToContainer(
                        MountableFile.forClasspathResource("my-app-realm-realm.json"),
                        "/opt/keycloak/data/import/my-app-realm-realm.json"
                )
                .waitingFor(Wait.forLogMessage(".*Realm 'my-app-realm' imported.*", 1));
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("keycloak.auth-server-url",
                () -> "http://localhost:" + KEYCLOAK_CONTAINER.getMappedPort(8080));
        registry.add("keycloak.realm", () -> "my-app-realm");
        registry.add("keycloak.client-id", () -> "my-app-client");
        registry.add("keycloak.client-secret", () -> "pYeKYYS6Yp1YziNjgDjQPHgtu7RbwPog");
        registry.add("keycloak.admin.username", () -> "my_user_manager");
        registry.add("keycloak.admin.password", () -> "my_user_manager_password");
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri",
                () -> "http://localhost:" + KEYCLOAK_CONTAINER.getMappedPort(8080) + "/realms/my-app-realm");
    }
}