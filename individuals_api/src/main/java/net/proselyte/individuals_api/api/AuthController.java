package net.proselyte.individuals_api.api;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import net.proselyte.individuals_api.exception.AuthException;
import net.proselyte.individuals_api.request.RefreshTokenRequest;
import net.proselyte.individuals_api.response.ErrorResponse;
import net.proselyte.individuals_api.request.RegistrationRequest;
import net.proselyte.individuals_api.request.LoginRequest;
import net.proselyte.individuals_api.service.KeycloakService;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakService keycloakService;

    @PostMapping("/registration")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegistrationRequest request) {
        if (Boolean.FALSE.equals(request.password().equals(request.confirmPassword()))) {
            return ResponseEntity.badRequest()
                    .body(new ErrorResponse("Password confirmation does not match", HttpStatus.BAD_REQUEST.value()));
        }

        try {
            var authResponse = keycloakService.registerUser(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(authResponse);
        } catch (AuthException ex) {
            return ResponseEntity.status(ex.getStatus())
                    .body(new ErrorResponse(ex.getMessage(), ex.getStatus().value()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Registration failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest request) {
        try {
            var authResponse = keycloakService.loginUser(request.email(), request.password());
            return ResponseEntity.ok(authResponse);
        } catch (AuthException ex) {
            return ResponseEntity.status(ex.getStatus())
                    .body(new ErrorResponse(ex.getMessage(), ex.getStatus().value()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Login failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            var authResponse = keycloakService.refreshToken(request.refreshToken());
            return ResponseEntity.ok(authResponse);
        } catch (AuthException ex) {
            return ResponseEntity.status(ex.getStatus())
                    .body(new ErrorResponse(ex.getMessage(), ex.getStatus().value()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("Token refresh failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }

    @GetMapping("/me")
    public ResponseEntity<?> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        try {
            var userInfo = keycloakService.getUserInfo(jwt);
            return ResponseEntity.ok(userInfo);
        } catch (AuthException ex) {
            return ResponseEntity.status(ex.getStatus())
                    .body(new ErrorResponse(ex.getMessage(), ex.getStatus().value()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(new ErrorResponse("User get info failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value()));
        }
    }
}
