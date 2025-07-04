package net.proselyte.individuals_api.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.proselyte.individuals_api.request.RefreshTokenRequest;
import net.proselyte.individuals_api.response.AuthResponse;
import net.proselyte.individuals_api.request.RegistrationRequest;
import net.proselyte.individuals_api.request.LoginRequest;
import net.proselyte.individuals_api.response.UserInfoResponse;
import net.proselyte.individuals_api.service.KeycloakService;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakService keycloakService;

    @PostMapping("/registration")
    public Mono<ResponseEntity<AuthResponse>> registerUser(@Valid @RequestBody RegistrationRequest request) {
        return Mono.just(request).flatMap(req -> keycloakService.registerUser(req)
                .map(authResponse -> ResponseEntity.status(HttpStatus.CREATED).body(authResponse)));
    }

    @PostMapping("/login")
    public Mono<AuthResponse> loginUser(@Valid @RequestBody Mono<LoginRequest> requestMono) {
        return requestMono.flatMap(request -> keycloakService.loginUser(request.email(), request.password()));
    }

    @PostMapping("/refresh-token")
    public Mono<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return keycloakService.refreshToken(request.refreshToken());
    }

    @GetMapping("/me")
    public Mono<UserInfoResponse> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        return keycloakService.getUserInfo(jwt);
    }
}
