//package jpabook.auctiongateway.config;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.MalformedJwtException;
//import io.jsonwebtoken.UnsupportedJwtException;
//import jpabook.auctiongateway.common.utils.JwtUtil;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.core.env.Environment;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpResponse;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//@Slf4j
//@Component
//public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {
//
//    Environment env;
//    private final JwtUtil jwtUtil;
//
//    public JwtAuthenticationFilter(Environment env, JwtUtil jwtUtil) {
//        super(Config.class);
//        this.env = env;
//        this.jwtUtil = jwtUtil;
//    }
//
//    public static class Config {
//        // 추가 설정
//    }
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            String token = exchange.getRequest().getHeaders().getFirst("Authorization");
//            jwtUtil.substringToken(token);
//            try {
//                Claims claims = jwtUtil.extractClaims(token);
//                Long userId = Long.valueOf(claims.getSubject());
//
//                if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//                    // userId 헤더 추가
//                    exchange.getRequest().mutate().header("userId", userId.toString());
//                } else {
//                    return onError(exchange, "Invalid user ID", HttpStatus.UNAUTHORIZED);
//                }
//
//            } catch (SecurityException | MalformedJwtException e) {
//                onError(exchange, "Invalid JWT signature, 유효하지 않는 JWT 서명입니다.", HttpStatus.UNAUTHORIZED);
//            } catch (ExpiredJwtException e) {
//                onError(exchange, "Expired JWT token, 만료된 JWT token 입니다.", HttpStatus.UNAUTHORIZED);
//            } catch (UnsupportedJwtException e) {
//                onError(exchange, "Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", HttpStatus.BAD_REQUEST);
//            } catch (Exception e) {
//                onError(exchange, "Internal server error", HttpStatus.INTERNAL_SERVER_ERROR);
//            }
//            return chain.filter(exchange);
//        };
//    }
//
//    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
//        ServerHttpResponse response = exchange.getResponse();
//        response.setStatusCode(httpStatus);
//
//        log.error(err);
//        return response.setComplete();
//    }
//}
