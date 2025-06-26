package net.proselyte.individuals_api;

import net.proselyte.individuals_api.response.AuthResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthControllerIT extends KeycloakTestBase {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    @DisplayName("Successful login should return valid access and refresh tokens")
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

    @Test
    @DisplayName("Login should return 401 when email is correct but password is wrong")
    void login_ShouldReturn401_WhenPasswordWrong() {
        webTestClient.post().uri("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
            {
                "email": "my_user_manager",
                "password": "wrongpassword"
            }
            """)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("Login should return 401 when user doesn't exist")
    void login_ShouldReturn401_WhenUserNotExist() {
        webTestClient.post().uri("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
            {
                "email": "notexist@example.com",
                "password": "anypassword"
            }
            """)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    @DisplayName("User registration should create new user and return auth tokens")
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
    @DisplayName("Registration should return 400 when password confirmation doesn't match")
    void registration_ShouldReturn400_WhenPasswordConfirmationMismatch() {
        webTestClient.post().uri("/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
            {
                "email": "newuser@example.com",
                "password": "SecurePassword123",
                "confirm_password": "DifferentPassword123"
            }
            """)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("Password confirmation does not match")
                .jsonPath("$.status").isEqualTo(400);
    }

    @Test
    @DisplayName("Registration should return 409 when user already exists")
    void registration_ShouldReturn409_WhenUserExists() {
        String existingEmail = "existing@example.com";

        webTestClient.post().uri("/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(String.format("""
            {
                "email": "%s",
                "password": "SecurePassword123",
                "confirm_password": "SecurePassword123"
            }
            """, existingEmail))
                .exchange()
                .expectStatus().isCreated();

        // 2. Пытаемся зарегистрировать того же пользователя снова
        webTestClient.post().uri("/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(String.format("""
            {
                "email": "%s",
                "password": "NewPassword123",
                "confirm_password": "NewPassword123"
            }
            """, existingEmail))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)  // Исправлено здесь
                .expectBody()
                .jsonPath("$.error").isEqualTo("User with this email already exists")
                .jsonPath("$.status").isEqualTo(409);
    }

    @Test
    @DisplayName("Refresh token endpoint should return new tokens when valid refresh token provided")
    void refreshToken_ShouldReturnNewTokens_WhenValidRefreshToken() {
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
    @DisplayName("Refresh token should return 401 when invalid refresh token provided")
    void refreshToken_ShouldReturn401_WhenInvalidToken() {
        webTestClient.post().uri("/v1/auth/refresh-token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
            {
                "refresh_token": "invalid.refresh.token"
            }
            """)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("Invalid or expired refresh token")
                .jsonPath("$.status").isEqualTo(401);
    }

    @Test
    @DisplayName("Current user endpoint should return authenticated user's information")
    void getCurrentUser_ShouldReturnUserInfo() {
        String token = webTestClient.post().uri("/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
                {
                    "email": "testuser@example.com",
                    "password": "testpassword"
                }
                """)
                .exchange()
                .returnResult(AuthResponse.class)
                .getResponseBody()
                .map(AuthResponse::accessToken)
                .blockFirst();

        webTestClient.get().uri("/v1/auth/me")
                .header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.email").isEqualTo("testuser@example.com");
    }
//
//    @Test
//    @DisplayName("Should return 401 when no token provided")
//    void getCurrentUser_NoToken_ShouldReturnUnauthorized() {
//        webTestClient.get().uri("/v1/auth/me")
//                .accept(MediaType.APPLICATION_JSON)
//                .exchange()
//                .expectStatus().isUnauthorized()
//                .expectBody()
//                .jsonPath("$.error").isEqualTo("Invalid or expired access token")
//                .jsonPath("$.status").isEqualTo(401);
//    }
//
//    @Test
//    @DisplayName("Should return 401 when invalid token provided")
//    void getCurrentUser_InvalidToken_ShouldReturnUnauthorized() {
//        webTestClient.get().uri("/v1/auth/me")
//                .header("Authorization", "Bearer invalid.token.here")
//                .accept(MediaType.APPLICATION_JSON)
//                .exchange()
//                .expectStatus().isUnauthorized()
//                .expectBody()
//                .jsonPath("$.error").isEqualTo("Invalid or expired access token")
//                .jsonPath("$.status").isEqualTo(401);
//    }
//
//    @Test
//    @DisplayName("Should return 401 when expired token provided")
//    void getCurrentUser_ExpiredToken_ShouldReturnUnauthorized() {
//        String expiredToken = "your.expired.token.here";
//
//        webTestClient.get().uri("/v1/auth/me")
//                .header("Authorization", "Bearer " + expiredToken)
//                .accept(MediaType.APPLICATION_JSON)
//                .exchange()
//                .expectStatus().isUnauthorized()
//                .expectBody()
//                .jsonPath("$.error").isEqualTo("Invalid or expired access token")
//                .jsonPath("$.status").isEqualTo(401);
//    }
}