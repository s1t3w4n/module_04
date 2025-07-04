package net.proselyte.individuals_api.service;

import net.proselyte.individuals_api.exception.AuthException;
import net.proselyte.individuals_api.response.AuthResponse;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

@Service
public class TokenService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    public Mono<AuthResponse> refreshToken(String refreshToken) {
        return WebClient.builder()
                .baseUrl(authServerUrl)
                .defaultHeader("Content-Type", "application/x-www-form-urlencoded")
                .build()
                .post()
                .uri("/realms/" + realm + "/protocol/openid-connect/token")
                .body(BodyInserters.fromFormData(createFormData(refreshToken)))
                .retrieve()
                .bodyToMono(AccessTokenResponse.class)
                .map(this::convertToAuthResponse)
                .onErrorResume(this::handleTokenRefreshError);
    }

    private MultiValueMap<String, String> createFormData(String refreshToken) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN);
        formData.add(OAuth2Constants.CLIENT_ID, clientId);
        formData.add(OAuth2Constants.CLIENT_SECRET, clientSecret);
        formData.add(OAuth2Constants.REFRESH_TOKEN, refreshToken);
        return formData;
    }

    private AuthResponse convertToAuthResponse(AccessTokenResponse response) {
        return new AuthResponse(
                response.getToken(),
                response.getExpiresIn(),
                response.getRefreshToken(),
                response.getTokenType()
        );
    }

    private Mono<AuthResponse> handleTokenRefreshError(Throwable ex) {
        if (ex instanceof WebClientResponseException) {
            return Mono.error(new AuthException("Invalid or expired refresh token", HttpStatus.UNAUTHORIZED));
        }
        return Mono.error(new AuthException(
                "Token refresh failed: " + ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR
        ));
    }
}
