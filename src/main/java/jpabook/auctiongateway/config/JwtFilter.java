package jpabook.auctiongateway.config;

import io.jsonwebtoken.Claims;
import jpabook.auctiongateway.common.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        log.info("request path: {}", path);

        // 인증 X
        if (path.startsWith("/api/v1/auth/")
                || path.equals("/error")
                || path.equals("/style.css")
                || path.startsWith("/api/v2/auctions/search")
                || path.startsWith("/api/v2/auctions/elasticsearch")
                || path.equals("/actuator/health")
                || path.equals("/health")
                || path.equals("/actuator/prometheus")
                || path.equals("/api/v1/points/buy/confirm")) {
            return chain.filter(exchange);
        }

        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
//            return chain.filter(exchange);
            return onError(exchange, "No Authorization Header Found", HttpStatus.UNAUTHORIZED);
        }

        String jwt = jwtUtil.substringToken(authorizationHeader);
        try {
            Claims claims = jwtUtil.extractClaims(jwt);
            if (claims == null) {
                return onError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
            }

            Long userId = Long.valueOf(claims.getSubject());

            if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                ServerHttpRequest decoratedRequest = new ServerHttpRequestDecorator(request) {
                    @Override
                    public HttpHeaders getHeaders() {
                        HttpHeaders headers = new HttpHeaders();
                        headers.putAll(super.getHeaders());
                        headers.add("userId", Long.toString(userId));
                        return headers;
                    }
                };

                ServerWebExchange mutatedExchange = exchange.mutate()
                        .request(decoratedRequest)
                        .build();

                return chain.filter(mutatedExchange);
            } else {
                return onError(exchange, "Invalid user ID", HttpStatus.UNAUTHORIZED);
            }

        } catch (Exception e) {
            return onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();
    }
}

