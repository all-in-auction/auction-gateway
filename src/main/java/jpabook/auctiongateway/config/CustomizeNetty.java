package jpabook.auctiongateway.config;

import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;

//@Component
public class CustomizeNetty implements WebServerFactoryCustomizer<NettyReactiveWebServerFactory> {
    @Override
    public void customize(NettyReactiveWebServerFactory factory) {
        factory.addServerCustomizers(httpServer -> httpServer.http2Settings(builder -> builder.maxHeaderListSize(65536)));
    }
}
