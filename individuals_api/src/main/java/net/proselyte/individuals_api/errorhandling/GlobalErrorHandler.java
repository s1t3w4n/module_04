package net.proselyte.individuals_api.errorhandling;

import net.proselyte.individuals_api.exception.AuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.result.method.annotation.ResponseEntityExceptionHandler;
import reactor.core.publisher.Mono;

import java.util.Map;

@ControllerAdvice
public class GlobalErrorHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler
    public Mono<ResponseEntity<?>> handleBusinessException(AuthException ex) {
        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(Map.of("error", ex.getMessage(), "status", ex.getStatus().value())));
    }

    @ExceptionHandler
    public Mono<ResponseEntity<?>> handleAllExceptions(Exception ex) {
        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                        "error", "Unexpected server error: " + ex.getMessage(),
                        "status", HttpStatus.INTERNAL_SERVER_ERROR.value())));
    }
}
