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
    static final java.util.regex.Pattern VALID_CORRELATION_ID = java.util.regex.Pattern.compile("^[A-Za-z0-9._-]{8,64}$");

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
            // Client-supplied IDs are echoed into logs and headers: accept only a safe, bounded token.
            if (correlationId == null || !VALID_CORRELATION_ID.matcher(correlationId).matches()) {
                correlationId = UUID.randomUUID().toString();
            }

            ServerHttpRequest request = exchange.getRequest()
                    .mutate()
                    .header(CorrelationHeaders.CORRELATION_ID, correlationId)
                    .build();
            // Set at commit time so error responses (which rebuild headers) still carry the ID.
            String id = correlationId;
            exchange.getResponse().beforeCommit(() -> {
                exchange.getResponse().getHeaders().set(CorrelationHeaders.CORRELATION_ID, id);
                return reactor.core.publisher.Mono.empty();
            });
            return chain.filter(exchange.mutate().request(request).build());
        };
    }
}

