package my.application.individuals_api.utils;

import my.application.individuals_api.exception.AuthException;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;

import static my.application.individuals_api.utils.Messages.PASSWORD_DOES_NOT_MATH;

public class ValidationUtils {
    public static Mono<Void> validatePassword(String password, String confirmPassword) {
        return Mono.defer(() -> {
            if (Boolean.FALSE.equals(password.equals(confirmPassword))) {
                return Mono.error(new AuthException(PASSWORD_DOES_NOT_MATH, HttpStatus.BAD_REQUEST));
            }
            return Mono.empty();
        });
    }
}
