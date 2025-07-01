package net.proselyte.individuals_api.service;

import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import net.proselyte.individuals_api.exception.AuthException;
import net.proselyte.individuals_api.response.AuthResponse;
import net.proselyte.individuals_api.request.RegistrationRequest;
import net.proselyte.individuals_api.response.UserInfoResponse;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class KeycloakService {

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

    public AuthResponse registerUser(RegistrationRequest request) {
        createUserInKeycloak(request);
        return loginUser(request.email(), request.password());
    }

    private void createUserInKeycloak(RegistrationRequest request) {
        try (var keycloakAdmin = KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(adminUsername)
                .password(adminPassword)
                .build()) {

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

            var realmResource = keycloakAdmin.realm(realm);
            var usersResource = realmResource.users();

            try (Response response = usersResource.create(user)) {
                if (response.getStatus() == HttpStatus.CONFLICT.value()) {
                    throw new AuthException("User with this email already exists", HttpStatus.CONFLICT);
                }
                if (response.getStatus() != HttpStatus.CREATED.value()) {
                    throw new AuthException("Failed to create user", HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }
        }
    }

    public AuthResponse loginUser(String username, String password) {
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
        } catch (NotAuthorizedException ex) {
            throw new AuthException("Invalid email or password", HttpStatus.UNAUTHORIZED);
        }
    }

    public AuthResponse refreshToken(String refreshToken) {
        try (var client = ClientBuilder.newClient()) {
            var form = new Form()
                    .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN)
                    .param(OAuth2Constants.CLIENT_ID, clientId)
                    .param(OAuth2Constants.CLIENT_SECRET, clientSecret)
                    .param(OAuth2Constants.REFRESH_TOKEN, refreshToken);
            var tokenResponse = client.target(authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .request()
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .post(Entity.form(form), AccessTokenResponse.class);
            return new AuthResponse(
                    tokenResponse.getToken(),
                    tokenResponse.getExpiresIn(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getTokenType()
            );
        } catch (Exception ex) {
            throw new AuthException("Invalid or expired refresh token", HttpStatus.UNAUTHORIZED);
        }
    }

    public UserInfoResponse getUserInfo(Jwt jwt) {
        String userId = jwt.getSubject();
        String email = jwt.getClaim("email");

        try (var keycloak = KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(adminUsername)
                .password(adminPassword)
                .build()) {
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(userId);
            UserRepresentation user = userResource.toRepresentation();
            if (Objects.isNull(user)) {
                throw new AuthException("User not found", HttpStatus.NOT_FOUND);
            }
        }
        return new UserInfoResponse(
                userId,
                email,
                extractRoles(jwt),
                jwt.getClaim("iat")
        );
    }

    private List<String> extractRoles(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (Objects.isNull(roles)) {
            return Collections.emptyList();
        }
        return roles;
    }
}
