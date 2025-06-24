package net.proselyte.individuals_api;

import net.proselyte.individuals_api.response.AuthResponse;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthControllerIT extends KeycloakTestBase {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    @Order(1)
    void login_ShouldReturnTokens() {
        webTestClient.post().uri("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                {
                    "email": "my_user_manager",
                    "password": "my_user_manager_password"
                }
                """)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.access_token").isNotEmpty()
                .jsonPath("$.refresh_token").isNotEmpty();
    }

    // Тест регистрации
    @Test
    @Order(2)
    void registration_ShouldCreateUser() {
        webTestClient.post().uri("/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.ALL)
                .bodyValue("""
                {
                    "email": "testuser@example.com",
                    "password": "testpassword",
                    "confirm_password": "testpassword"
                }
                """)
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.token_type").isEqualTo("Bearer");
    }

    @Test
    @Order(3)
    void refreshToken_ShouldReturnNewTokens_WhenValidRefreshToken() {
        // 1. Получаем исходные токены через логин
        String refreshToken = webTestClient.post().uri("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                {
                    "email": "testuser@example.com",
                    "password": "testpassword"
                }
                """)
                .exchange()
                .expectStatus().isOk()
                .returnResult(AuthResponse.class)
                .getResponseBody()
                .map(AuthResponse::refreshToken)
                .blockFirst();

        // 2. Обновляем токен
        webTestClient.post().uri("/v1/auth/refresh-token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                {
                    "refresh_token": "%s"
                }
                """.formatted(refreshToken))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.access_token").isNotEmpty()
                .jsonPath("$.refresh_token").isNotEmpty()
                .jsonPath("$.token_type").isEqualTo("Bearer")
                .jsonPath("$.expires_in").isNumber();
    }

    @Test
    @Order(4)
    void getCurrentUser_ShouldReturnUserInfo() {
        // 1. Получаем токен
        String token = webTestClient.post().uri("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                {
                    "email": "testuser@example.com",
                    "password": "testpassword"
                }
                """)
                .exchange()
                .returnResult(Void.class)
                .getResponseHeaders()
                .getFirst("Authorization");

        webTestClient.get().uri("/v1/auth/me")
                .header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("testuser@example.com");
    }
}