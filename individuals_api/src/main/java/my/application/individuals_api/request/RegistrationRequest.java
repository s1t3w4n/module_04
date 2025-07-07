package my.application.individuals_api.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegistrationRequest(
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8) String password,
        @NotBlank @JsonProperty("confirm_password") String confirmPassword
) {}