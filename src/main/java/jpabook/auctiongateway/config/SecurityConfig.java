package jpabook.auctiongateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(
                                "/api/v1/auth/**",
                                "/error",
                                "/style.css",
                                "/payment/**",
                                "/api/v1/points/buy/confirm",
                                "/actuator/prometheus",
                                "/api/v2/auctions/search",
                                "/api/v2/auctions/elasticsearch",
                                "/actuator/health",
                                "/health",
                                "/*/v3/api-docs/**",
                                "/v3/api-docs/**",
                                "/v3/api-docs",
                                "/swagger-ui/**",
                                "/swagger-ui/index.html",
                                "/webjars/swagger-ui/o",
                                "/v3/api-docs/swagger-config",
                                "/*/swagger-ui/index.html",
                                "/points/**",
                                "/auction/**"
                        ).permitAll()
                        .pathMatchers("/api/v2/admin/**").hasAuthority("ADMIN")
                        .anyExchange().authenticated()
                )
                .addFilterAt(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }
}
