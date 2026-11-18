package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(EventRepository.class)
@ImportAutoConfiguration(JacksonAutoConfiguration.class)
class EventRepositoryTest {

    @Autowired
    private EventRepository repository;

    @Test
    void insertsAndReadsRecentEvents() {
        SecurityEvent older = event("evt-old", Instant.now().minusSeconds(60), "LOGIN_FAILURE");
        SecurityEvent newer = event("evt-new", Instant.now(), "MALWARE_DETECTED");
        SecurityEvent newest = event("evt-dup", Instant.now().plusSeconds(120), "PORT_SCAN");

        long before = repository.count();
        repository.insert(older);
        repository.insert(newer);
        repository.insert(newest);
        repository.insert(newest);

        assertEquals(before + 3, repository.count(), "the duplicate insert is ignored");
        assertEquals("PORT_SCAN", repository.recent(1).get(0).eventType());
        assertEquals(2, repository.recent(2).size());
    }

    private SecurityEvent event(String id, Instant timestamp, String eventType) {
        return new SecurityEvent(
                id,
                timestamp,
                eventType,
                EventSeverity.HIGH,
                "GENERAL",
                "192.168.1.10",
                "host-" + id,
                "10.0.0.1",
                443,
                "analyst",
                "Persisted event " + id
        );
    }

    @org.junit.jupiter.api.Test
    void attributesRoundTrip() {
        com.enterprise.siem.common.model.SecurityEvent event = new com.enterprise.siem.common.model.SecurityEvent(
                "attr-1", java.time.Instant.parse("2026-01-01T00:00:00Z"), "NETWORK_FLOW",
                com.enterprise.siem.common.model.EventSeverity.INFO, "NET", "10.0.0.1", null, "8.8.8.8", 443, null, null,
                2, java.util.Map.of("bytesOut", "1234"));
        repository.insert(event);
        org.assertj.core.api.Assertions.assertThat(repository.findById("attr-1").orElseThrow().attributes())
                .containsEntry("bytesOut", "1234");
    }
}
