package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(EventRepository.class)
class EventRepositoryTest {

    @Autowired
    private EventRepository repository;

    @Test
    void insertsAndReadsRecentEvents() {
        SecurityEvent older = event("evt-old", Instant.now().minusSeconds(60), "LOGIN_FAILURE");
        SecurityEvent newer = event("evt-new", Instant.now(), "MALWARE_DETECTED");
        SecurityEvent newest = event("evt-dup", Instant.now().plusSeconds(1), "PORT_SCAN");

        repository.insert(older);
        repository.insert(newer);
        repository.insert(newest);
        repository.insert(newest);

        assertEquals(3, repository.count());
        assertEquals(3, repository.recent(10).size());
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
}