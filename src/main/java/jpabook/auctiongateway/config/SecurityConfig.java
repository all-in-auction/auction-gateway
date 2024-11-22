package jpabook.auctiongateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;

import java.net.URI;

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
                                "/",
                                "/*/v3/api-docs/**",
                                "/v3/api-docs/**",
                                "/v3/api-docs",
                                "/swagger-ui/**",
                                "/swagger-ui/index.html",
                                "/webjars/swagger-ui/o",
                                "/v3/api-docs/swagger-config",
                                "/*/swagger-ui/index.html"
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

    @Bean
    public WebFilter redirectRootToSwagger() {
        return (exchange, chain) -> {
            if ("/".equals(exchange.getRequest().getPath().value())) {
                exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                exchange.getResponse().getHeaders().setLocation(URI.create("/swagger-ui/index.html"));
                exchange.getResponse().getHeaders().add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                exchange.getResponse().getHeaders().add("Pragma", "no-cache");
                return exchange.getResponse().setComplete();
            }
            return chain.filter(exchange);
        };
    }
}
