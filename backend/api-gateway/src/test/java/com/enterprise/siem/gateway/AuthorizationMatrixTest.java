package com.enterprise.siem.gateway;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * The gateway's RBAC matrix, asserted cell by cell. "Allowed" means the gateway forwarded the
 * request (upstreams are unreachable in this test, so the status is a 5xx), "denied" means 403.
 * Each backend service enforces the same matrix again; this is the outer layer.
 */
@SpringBootTest(properties = {
        "AUTH_SERVICE_URL=http://127.0.0.1:1", "INGESTION_SERVICE_URL=http://127.0.0.1:1",
        "DETECTION_SERVICE_URL=http://127.0.0.1:1", "ALERT_SERVICE_URL=http://127.0.0.1:1",
        "INCIDENT_SERVICE_URL=http://127.0.0.1:1", "THREAT_INTEL_SERVICE_URL=http://127.0.0.1:1",
        "AUDIT_SERVICE_URL=http://127.0.0.1:1", "SEARCH_SERVICE_URL=http://127.0.0.1:1"
})
@AutoConfigureWebTestClient
class AuthorizationMatrixTest {
    private static final Set<String> ALL = Set.of("ADMIN", "SOC_MANAGER", "SECURITY_ANALYST", "VIEWER");
    private static final Set<String> ANALYSTS = Set.of("ADMIN", "SOC_MANAGER", "SECURITY_ANALYST");
    private static final Set<String> MANAGERS = Set.of("ADMIN", "SOC_MANAGER");
    private static final Set<String> ADMIN = Set.of("ADMIN");

    @Autowired
    private WebTestClient client;

    record Cell(HttpMethod method, String path, Set<String> allowed) {
    }

    static final List<Cell> MATRIX = List.of(
            new Cell(HttpMethod.GET, "/api/events", ALL),
            new Cell(HttpMethod.POST, "/api/events", ANALYSTS),
            new Cell(HttpMethod.GET, "/api/alerts/search", ALL),
            new Cell(HttpMethod.POST, "/api/alerts/A1/resolve", ANALYSTS),
            new Cell(HttpMethod.GET, "/api/incidents", ALL),
            new Cell(HttpMethod.PATCH, "/api/incidents/INC-1", ANALYSTS),
            new Cell(HttpMethod.GET, "/api/rules", ALL),
            new Cell(HttpMethod.POST, "/api/rules/test", ANALYSTS),
            new Cell(HttpMethod.POST, "/api/rules/SIEM-1001/disable", MANAGERS),
            new Cell(HttpMethod.GET, "/api/detection/summary", ALL),
            new Cell(HttpMethod.GET, "/api/threat-intel/indicators", ALL),
            new Cell(HttpMethod.POST, "/api/threat-intel/indicators", MANAGERS),
            new Cell(HttpMethod.GET, "/api/search/events", ALL),
            new Cell(HttpMethod.GET, "/api/audit/events", MANAGERS),
            new Cell(HttpMethod.GET, "/api/users", ADMIN),
            new Cell(HttpMethod.GET, "/actuator/gateway/routes", Set.of()),
            new Cell(HttpMethod.GET, "/actuator/env", Set.of())
    );

    static Stream<Arguments> cells() {
        return MATRIX.stream().flatMap(cell -> ALL.stream().sorted().map(role -> Arguments.of(cell, role)));
    }

    @ParameterizedTest(name = "{1} {0}")
    @MethodSource("cells")
    void enforcesMatrix(Cell cell, String role) {
        HttpStatus status = HttpStatus.valueOf(client.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_" + role)))
                .method(cell.method()).uri(cell.path())
                .exchange()
                .returnResult(Void.class)
                .getStatus().value());
        if (cell.allowed().contains(role)) {
            assertThat(status).as("%s should reach the upstream", role).isNotIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
        } else {
            // Disabled actuator endpoints may also answer 404; either way nothing is disclosed.
            assertThat(status).as("%s should be denied", role).isIn(HttpStatus.FORBIDDEN, HttpStatus.NOT_FOUND);
        }
    }

    @org.junit.jupiter.api.Test
    void anonymousRequestsAreRejected() {
        client.get().uri("/api/alerts").exchange().expectStatus().isUnauthorized();
    }

    @org.junit.jupiter.api.Test
    void unsafeCorrelationIdsAreReplaced() {
        // Route filters only run on proxied requests, so use an authenticated /api call.
        WebTestClient viewer = client.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_VIEWER")));
        String echoed = viewer.get().uri("/api/alerts")
                .header("X-Correlation-Id", "<script>alert(1)</script> forged=" + "x".repeat(200))
                .exchange().returnResult(Void.class).getResponseHeaders().getFirst("X-Correlation-Id");
        assertThat(echoed).matches("^[A-Za-z0-9._-]{8,64}$");
        String kept = viewer.get().uri("/api/alerts").header("X-Correlation-Id", "req-12345678")
                .exchange().returnResult(Void.class).getResponseHeaders().getFirst("X-Correlation-Id");
        assertThat(kept).isEqualTo("req-12345678");
    }

    @org.junit.jupiter.api.Test
    void oversizedBodiesAreRejected() {
        client.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .post().uri("/api/events/batch")
                .header("Content-Type", "application/json")
                .header("Content-Length", String.valueOf(3 * 1024 * 1024))
                .bodyValue(new byte[3 * 1024 * 1024])
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONTENT_TOO_LARGE);
    }
}
