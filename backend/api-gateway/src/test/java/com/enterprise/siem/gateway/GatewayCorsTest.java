package com.enterprise.siem.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(properties = "siem.cors.allowed-origin=http://localhost:15173")
@AutoConfigureWebTestClient
class GatewayCorsTest {
    private static final String DASHBOARD = "http://localhost:15173";

    private WebTestClient client;

    @Autowired
    void setClient(WebTestClient client) {
        // An absolute base URL gives requests a host, as a browser's would; CORS checks need it.
        this.client = client.mutate().baseUrl("http://localhost:18080").build();
    }

    @Test
    void rejectedRequestsStillCarryCorsHeaders() {
        // Without CORS headers on a 401/403 the browser hides the status from the dashboard.
        client.get().uri("/api/audit/internal/status")
                .header(HttpHeaders.ORIGIN, DASHBOARD)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, DASHBOARD);
    }

    @Test
    void preflightIsAnsweredForTheDashboardOrigin() {
        client.options().uri("/api/alerts")
                .header(HttpHeaders.ORIGIN, DASHBOARD)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "authorization,content-type")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, DASHBOARD);
    }

    @Test
    void otherOriginsGetNoCorsHeaders() {
        client.get().uri("/api/audit/internal/status")
                .header(HttpHeaders.ORIGIN, "https://evil.example")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
    }
}
