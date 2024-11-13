//package jpabook.auctiongateway.config;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
//import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
//import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.web.server.SecurityWebFilterChain;
//import org.springframework.web.server.WebFilter;
//
//@Configuration
//@EnableWebFluxSecurity
//@RequiredArgsConstructor
//public class SecurityConfig {
//
//    private final JwtAuthenticationFilter jwtAuthenticationFilter;
//
//    @Bean
//    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
//        return http
//                .authorizeExchange(exchanges -> exchanges
//                        .pathMatchers(
//                                "/api/v1/auth/**",
//                                "/error",
//                                "/style.css",
//                                "/payment/**",
//                                "/api/v1/points/buy/confirm",
//                                "/actuator/prometheus",
//                                "/api/v2/auctions/search",
//                                "/api/v2/auctions/elasticsearch",
//                                "/actuator/health",
//                                "/health"
//                        ).permitAll()
//                        .anyExchange().authenticated()
//                )
//                .addFilterAt((WebFilter) jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
//                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
//                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
//                .csrf(ServerHttpSecurity.CsrfSpec::disable)
//                .cors(ServerHttpSecurity.CorsSpec::disable)
//                .build();
//    }
//}
