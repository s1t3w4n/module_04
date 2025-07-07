package my.application.individuals_api.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public record AuthResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("token_type") String tokenType
) {
}
