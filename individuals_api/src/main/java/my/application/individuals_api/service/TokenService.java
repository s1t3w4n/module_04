package my.application.individuals_api.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import my.application.individuals_api.exception.AuthException;
import my.application.individuals_api.integration.KeycloakConstants;
import my.application.individuals_api.integration.KeycloakIntegration;
import my.application.individuals_api.response.AuthResponse;
import my.application.individuals_api.utils.Messages;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@AllArgsConstructor
public class TokenService {

    private final KeycloakIntegration keycloakIntegration;

    public Mono<AuthResponse> refreshToken(String refreshToken) {
        log.info("Entering refreshToken method");
        return keycloakIntegration.getUserToken(createRefreshFormData(refreshToken))
                .onErrorResume(WebClientResponseException.class,
                        ex -> Mono.error(new AuthException(Messages.INVALID_OR_EXPIRED_REFRESH_TOKEN, HttpStatus.UNAUTHORIZED)));
    }

    private MultiValueMap<String, String> createRefreshFormData(String refreshToken) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add(KeycloakConstants.GRANT_TYPE, KeycloakConstants.REFRESH_TOKEN);
        formData.add(KeycloakConstants.REFRESH_TOKEN, refreshToken);
        return formData;
    }
}
