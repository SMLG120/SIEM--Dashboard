package com.enterprise.siem.gateway;

import com.enterprise.siem.common.correlation.CorrelationHeaders;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.UUID;

@SpringBootApplication
public class ApiGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    GlobalFilter correlationIdFilter() {
        return (exchange, chain) -> {
            String correlationId = exchange.getRequest()
                    .getHeaders()
                    .getFirst(CorrelationHeaders.CORRELATION_ID);
            if (correlationId == null || correlationId.isBlank()) {
                correlationId = UUID.randomUUID().toString();
            }

            ServerHttpRequest request = exchange.getRequest()
                    .mutate()
                    .header(CorrelationHeaders.CORRELATION_ID, correlationId)
                    .build();
            exchange.getResponse().getHeaders().set(CorrelationHeaders.CORRELATION_ID, correlationId);
            return chain.filter(exchange.mutate().request(request).build());
        };
    }
}

