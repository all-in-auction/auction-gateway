package jpabook.auctiongateway.config;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ForwardedHeaderFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Forwarded 헤더 중복 제거
        List<String> forwardedHeaders = exchange.getRequest().getHeaders().get("Forwarded");
        if (forwardedHeaders != null && forwardedHeaders.size() > 1) {
            List<String> uniqueForwardedHeaders = forwardedHeaders.stream()
                    .distinct()
                    .collect(Collectors.toList());
            exchange.mutate().request(exchange.getRequest().mutate().headers(
                    headers -> headers.put("Forwarded", uniqueForwardedHeaders)
            ).build()).build();
        }

        return chain.filter(exchange);
    }

}
