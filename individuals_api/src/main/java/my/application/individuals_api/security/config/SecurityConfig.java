package my.application.individuals_api.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableReactiveMethodSecurity
public class SecurityConfig {

    private final CustomBearerTokenServerAuthenticationEntryPoint authenticationEntryPoint
            = new CustomBearerTokenServerAuthenticationEntryPoint();
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/v1/auth/me").authenticated()
                        .pathMatchers("/v1/auth/**").permitAll()
                        .pathMatchers("/actuator/**").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(
                                        new ReactiveJwtAuthenticationConverterAdapter(
                                                jwtAuthenticationConverter()
                                        )
                                )
                        )
                        .authenticationEntryPoint(authenticationEntryPoint)
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakJwtAuthenticationConverter());
        return converter;
    }
}
