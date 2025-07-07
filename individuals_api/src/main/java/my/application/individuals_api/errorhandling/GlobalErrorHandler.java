package my.application.individuals_api.errorhandling;

import lombok.extern.slf4j.Slf4j;
import my.application.individuals_api.exception.AuthException;
import my.application.individuals_api.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.result.method.annotation.ResponseEntityExceptionHandler;
import reactor.core.publisher.Mono;

@Slf4j
@ControllerAdvice
public class GlobalErrorHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler
    public Mono<ResponseEntity<ErrorResponse>> handleBusinessException(AuthException ex) {
        log.error("AuthException occurred: {} - Status: {}", ex.getMessage(), ex.getStatus());
        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(new ErrorResponse(ex.getMessage(), ex.getStatus().value())));
    }

    @ExceptionHandler
    public Mono<ResponseEntity<ErrorResponse>> handleAllExceptions(Exception ex) {
        log.error("Unexpected exception occurred: {}", ex.getMessage(), ex);
        return Mono.just(ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("Unexpected server error: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR.value())));
    }
}
