package my.application.individuals_api.model;

import my.application.individuals_api.integration.KeycloakConstants;

import java.util.List;

public record KeycloakUserCreateBody(
        String username,
        String email,
        boolean enabled,
        List<Credential> credentials
) {
    public record Credential(
            String type,
            String value,
            boolean temporary
    ) {}

    public static KeycloakUserCreateBody from(String email, String password) {
        return new KeycloakUserCreateBody(
                email,
                email,
                true,
                List.of(new Credential(
                        KeycloakConstants.PASSWORD,
                        password,
                        false
                ))
        );
    }
}