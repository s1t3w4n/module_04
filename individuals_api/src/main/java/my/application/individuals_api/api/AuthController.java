package my.application.individuals_api.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import my.application.individuals_api.request.RefreshTokenRequest;
import my.application.individuals_api.response.AuthResponse;
import my.application.individuals_api.request.RegistrationRequest;
import my.application.individuals_api.request.LoginRequest;
import my.application.individuals_api.response.UserInfoResponse;
import my.application.individuals_api.service.TokenService;
import my.application.individuals_api.service.UserService;
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

    private final UserService userService;
    private final TokenService tokenService;

    @PostMapping("/registration")
    public Mono<ResponseEntity<AuthResponse>> registerUser(@Valid @RequestBody RegistrationRequest request) {
        return Mono.just(request).flatMap(req -> userService.registerUser(req)
                .map(authResponse -> ResponseEntity.status(HttpStatus.CREATED).body(authResponse)));
    }

    @PostMapping("/login")
    public Mono<AuthResponse> loginUser(@Valid @RequestBody Mono<LoginRequest> requestMono) {
        return requestMono.flatMap(request -> userService.loginUser(request.email(), request.password()));
    }

    @PostMapping("/refresh-token")
    public Mono<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return tokenService.refreshToken(request.refreshToken());
    }

    @GetMapping("/me")
    public Mono<UserInfoResponse> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        return userService.getUserInfo(jwt);
    }
}
