package jpabook.auctiongateway.config;

import io.jsonwebtoken.Claims;
import jpabook.auctiongateway.common.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        log.info("request path: {}", path);

        // 인증이 필요 없는 경로 필터링
        if (isExcludedPath(path)) {
            return chain.filter(exchange);
        }

        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return onError(exchange, "No Authorization Header Found", HttpStatus.UNAUTHORIZED);
        }

        String jwt = jwtUtil.substringToken(authorizationHeader);
        try {
            Claims claims = jwtUtil.extractClaims(jwt);
            if (claims == null) {
                return onError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
            }

            Long userId = Long.valueOf(claims.getSubject());

            if (userId != null) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userId, null, null);

                ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
                    @Override
                    public HttpHeaders getHeaders() {
                        HttpHeaders headers = new HttpHeaders();
                        headers.putAll(super.getHeaders());
                        headers.put("userId", Collections.singletonList(Long.toString(userId)));
                        headers.set(HttpHeaders.AUTHORIZATION, authorizationHeader);
                        return headers;
                    }
                };

                ServerWebExchange mutatedExchange = exchange.mutate()
                        .request(mutatedRequest)
                        .build();

                return chain.filter(mutatedExchange)
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
            } else {
                return onError(exchange, "Invalid user ID", HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            log.error("Error while processing JWT: ", e);
            return onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    private boolean isExcludedPath(String path) {
        return path.startsWith("/api/v1/auth/") ||
                path.startsWith("/payment/") ||
                path.startsWith("/swagger-ui/") ||
                path.startsWith("/v3/api-docs/") ||
                path.startsWith("/api/v1/points/v3/api-docs/") ||
                path.startsWith("/api/v1/points/swagger-ui/") ||
                path.equals("/error") ||
                path.equals("/style.css") ||
                path.startsWith("/api/v2/auctions/search") ||
                path.startsWith("/api/v2/auctions/elasticsearch") ||
                path.equals("/actuator/health") ||
                path.equals("/health") ||
                path.equals("/actuator/prometheus") ||
                path.equals("/api/v1/points/buy/confirm") ||
                path.equals("/swagger-ui/index.html") ||
                path.equals("/v3/api-docs") ||
                path.equals("/api/v1/points/v3/api-docs") ||
                path.equals("/api/v1/points/swagger-ui") ||
                path.equals("/swagger-ui.html");
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        log.error(err);
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }
}
