package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
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
}