package my.application.individuals_api.response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;

public record UserInfoResponse(
        String id,
        String email,
        List<String> roles,
        @JsonProperty("created_at") Instant createdAt
) {}
