package com.enterprise.siem.threatintel;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(IndicatorRepository.class)
class IndicatorMatcherTest {
    @Autowired
    private IndicatorRepository repository;

    private IndicatorMatcher matcher;

    @BeforeEach
    void setUp() {
        matcher = new IndicatorMatcher(repository, new SimpleMeterRegistry());
        DemoIndicatorSeeder.DEMO.forEach(repository::insert);
    }

    private static SecurityEvent event(String id, String src, String dst, Map<String, String> attributes) {
        return new SecurityEvent(id, Instant.parse("2026-01-15T09:00:00Z"), "OUTBOUND_CONNECTION", EventSeverity.INFO,
                "NET", src, "wks-1", dst, 443, "alice", null, 2, attributes);
    }

    @Test
    void recordsSightingsForNetworkAndFileIndicatorsOnce() {
        SecurityEvent beacon = event("e1", "10.0.4.33", "203.0.113.140", Map.of());
        assertThat(matcher.match(beacon)).isEqualTo(1);
        assertThat(matcher.match(beacon)).as("redelivery").isZero();

        SecurityEvent eicar = event("e2", "10.0.0.8", "10.0.0.9",
                Map.of("fileHash", "44D88612FEA8A8F36DE82E1278ABB02F"));
        assertThat(matcher.match(eicar)).as("hash matched case-insensitively").isEqualTo(1);

        assertThat(repository.sightings(null, 10)).extracting(Sighting::eventId).containsExactlyInAnyOrder("e1", "e2");
        assertThat(repository.sightings("IOC-DEMO-0001", 10)).singleElement()
                .satisfies(s -> assertThat(s.field()).isEqualTo("destinationIp"));
    }

    @Test
    void ignoresDeactivatedAndExpiredIndicators() {
        repository.deactivate("IOC-DEMO-0002");
        assertThat(matcher.match(event("e3", "198.51.100.23", "10.0.0.1", Map.of()))).isZero();

        repository.insert(new Indicator("IOC-OLD", IndicatorType.IP, "192.0.2.77", EventSeverity.LOW, "expired",
                Indicator.SOURCE_ANALYST, "analyst", Instant.parse("2025-01-01T00:00:00Z"),
                Instant.parse("2025-06-01T00:00:00Z"), true));
        assertThat(matcher.match(event("e4", "192.0.2.77", "10.0.0.1", Map.of()))).isZero();
    }

    @Test
    void duplicateIndicatorsAreRejected() {
        assertThat(repository.insert(DemoIndicatorSeeder.DEMO.getFirst())).isFalse();
    }

    @Test
    void indicatorValuesAreValidatedAndCanonicalised() {
        assertThat(IndicatorType.DOMAIN.canonical(" C2.Example.NET ")).isEqualTo("c2.example.net");
        assertThat(IndicatorType.IP.canonical("2001:DB8::1")).isEqualTo("2001:db8::1");
        assertThatThrownBy(() -> IndicatorType.IP.canonical("evil.example")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IndicatorType.SHA256.canonical("abc")).isInstanceOf(IllegalArgumentException.class);
        assertThat(DemoIndicatorSeeder.DEMO).allSatisfy(i -> {
            assertThat(i.source()).isEqualTo(Indicator.SOURCE_SIMULATED_DEMO);
            assertThat(i.type().canonical(i.value())).isEqualTo(i.value());
        });
    }
}
