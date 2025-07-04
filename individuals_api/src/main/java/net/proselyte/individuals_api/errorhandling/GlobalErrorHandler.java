package net.proselyte.individuals_api.errorhandling;

import net.proselyte.individuals_api.exception.AuthException;
import net.proselyte.individuals_api.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.result.method.annotation.ResponseEntityExceptionHandler;
import reactor.core.publisher.Mono;

@ControllerAdvice
public class GlobalErrorHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler
    public Mono<ResponseEntity<?>> handleBusinessException(AuthException ex) {
        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(new ErrorResponse(ex.getMessage(), ex.getStatus().value())));
    }

    @ExceptionHandler
    public Mono<ResponseEntity<?>> handleAllExceptions(Exception ex) {
        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("Unexpected server error: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value())));
    }
}
