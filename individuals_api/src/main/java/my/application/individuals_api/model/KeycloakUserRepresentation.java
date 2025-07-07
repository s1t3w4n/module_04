package my.application.individuals_api.model;

import com.fasterxml.jackson.annotation.JsonProperty;


public record KeycloakUserRepresentation(
        @JsonProperty("id") String id,
        @JsonProperty("email") String email,
        @JsonProperty("createdTimestamp") Long createdTimestamp) {
}
