package my.application.individuals_api.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import my.application.individuals_api.exception.AuthException;
import my.application.individuals_api.integration.KeycloakConstants;
import my.application.individuals_api.integration.KeycloakIntegration;
import my.application.individuals_api.request.RegistrationRequest;
import my.application.individuals_api.response.AuthResponse;
import my.application.individuals_api.response.UserInfoResponse;
import my.application.individuals_api.utils.ValidationUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Instant;

import static my.application.individuals_api.utils.Messages.INVALID_EMAIL_OR_PASSWORD;

@Slf4j
@Service
@AllArgsConstructor
public class UserService {
    private final KeycloakIntegration keycloakIntegration;

    public Mono<AuthResponse> registerUser(RegistrationRequest request) {
        log.info("Entering registerUser method with email: {}", request.email());
        return ValidationUtils.validatePassword(request.password(), request.confirmPassword())
                .then(keycloakIntegration.getAdminAccessToken())
                .flatMap(adminAccessToken -> keycloakIntegration.createUser(adminAccessToken, request.email(), request.password())
                        .then(loginUser(request.email(), request.password())));
    }

    public Mono<AuthResponse> loginUser(String username, String password) {
        log.info("Entering loginUser method for username: {}", username);
        return keycloakIntegration.getUserToken(createLoginFormData(username, password))
                .onErrorResume(WebClientResponseException.class,
                        ex -> Mono.error(new AuthException(INVALID_EMAIL_OR_PASSWORD, HttpStatus.UNAUTHORIZED)));
    }

    public Mono<UserInfoResponse> getUserInfo(Jwt jwt) {
        log.info("Entering getUserInfo method for user ID: {}", jwt.getSubject());
        return keycloakIntegration.getAdminAccessToken()
                .flatMap(adminAccessToken -> keycloakIntegration.getUserById(adminAccessToken, jwt.getSubject())
                        .publishOn(Schedulers.boundedElastic())
                        .map(keycloakUserRepresentation -> new UserInfoResponse(
                                keycloakUserRepresentation.id(),
                                keycloakUserRepresentation.email(),
                                keycloakIntegration.getRolesByUserId(adminAccessToken, jwt.getSubject()).block(),
                                Instant.ofEpochMilli(keycloakUserRepresentation.createdTimestamp()))));
    }

    private MultiValueMap<String, String> createLoginFormData(String username, String password) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add(KeycloakConstants.GRANT_TYPE, KeycloakConstants.PASSWORD);
        formData.add(KeycloakConstants.USERNAME, username);
        formData.add(KeycloakConstants.PASSWORD, password);
        return formData;
    }
}
