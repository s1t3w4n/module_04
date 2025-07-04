package net.proselyte.individuals_api.service;

import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import net.proselyte.individuals_api.exception.AuthException;
import net.proselyte.individuals_api.request.RegistrationRequest;
import net.proselyte.individuals_api.response.AuthResponse;
import net.proselyte.individuals_api.response.UserInfoResponse;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
public class UserService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    public Mono<AuthResponse> registerUser(RegistrationRequest request) {
        return createUserInKeycloak(request)
                .then(loginUser(request.email(), request.password()));
    }

    private Mono<Void> createUserInKeycloak(RegistrationRequest request) {
        return Mono.using(
                () -> KeycloakBuilder.builder()
                        .serverUrl(authServerUrl)
                        .realm(realm)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .username(adminUsername)
                        .password(adminPassword)
                        .build(),
                keycloakAdmin -> Mono.fromCallable(() -> {
                    var user = getUserRepresentation(request);
                    try (Response response = keycloakAdmin.realm(realm).users().create(user)) {
                        if (response.getStatus() == HttpStatus.CONFLICT.value()) {
                            throw new AuthException("User with this email already exists", HttpStatus.CONFLICT);
                        }
                        if (response.getStatus() != HttpStatus.CREATED.value()) {
                            throw new AuthException("Failed to create user", HttpStatus.INTERNAL_SERVER_ERROR);
                        }
                    }
                    return null;
                }),
                keycloak -> Optional.ofNullable(keycloak).ifPresent(Keycloak::close)
        );
    }

    private static UserRepresentation getUserRepresentation(RegistrationRequest request) {
        var user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(request.email());
        user.setEmail(request.email());
        user.setEmailVerified(true);

        var credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(request.password());
        credential.setTemporary(false);
        user.setCredentials(List.of(credential));
        return user;
    }

    public Mono<AuthResponse> loginUser(String username, String password) {
        return Mono.fromCallable(() -> {
                    try (var keycloak = KeycloakBuilder.builder()
                            .serverUrl(authServerUrl)
                            .realm(realm)
                            .clientId(clientId)
                            .clientSecret(clientSecret)
                            .username(username)
                            .password(password)
                            .build()) {
                        var tokenResponse = keycloak.tokenManager().getAccessToken();
                        return new AuthResponse(
                                tokenResponse.getToken(),
                                tokenResponse.getExpiresIn(),
                                tokenResponse.getRefreshToken(),
                                tokenResponse.getTokenType()
                        );
                    }
                })
                .onErrorResume(NotAuthorizedException.class, ex ->
                        Mono.error(new AuthException("Invalid email or password", HttpStatus.UNAUTHORIZED)));
    }

    public Mono<UserInfoResponse> getUserInfo(Jwt jwt) {
        var userId = jwt.getSubject();
        String email = jwt.getClaim("email");
        var roles = extractRoles(jwt);
        Instant iat = jwt.getClaim("iat");
        return Mono.using(
                () -> KeycloakBuilder.builder()
                        .serverUrl(authServerUrl)
                        .realm(realm)
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .username(adminUsername)
                        .password(adminPassword)
                        .build(),
                keycloak -> Mono.fromCallable(() -> {
                    var user = keycloak.realm(realm)
                            .users()
                            .get(userId)
                            .toRepresentation();
                    return Optional.ofNullable(user)
                            .orElseThrow(() -> new AuthException("User not found", HttpStatus.NOT_FOUND));
                }),
                keycloak -> Optional.ofNullable(keycloak).ifPresent(Keycloak::close)
        ).thenReturn(new UserInfoResponse(
                userId,
                email,
                roles,
                iat
        )).onErrorResume(AuthException.class, Mono::error);
    }

    private List<String> extractRoles(Jwt jwt) {
        var roles = jwt.getClaimAsStringList("roles");
        if (Objects.isNull(roles)) {
            return Collections.emptyList();
        }
        return roles;
    }
}
