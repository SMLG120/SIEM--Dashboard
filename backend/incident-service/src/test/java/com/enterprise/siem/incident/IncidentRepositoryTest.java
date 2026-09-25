package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentNote;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import com.enterprise.siem.incident.model.TimelineEntry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({IncidentRepository.class, JacksonAutoConfiguration.class})
class IncidentRepositoryTest {

    @Autowired
    private IncidentRepository repository;

    @Test
    void persistsAndReloadsIncidentWithChildren() {
        Instant now = Instant.now();
        Incident incident = new Incident(
                "INC-ABC123",
                "Suspicious activity from 10.0.0.5",
                "Correlated incident",
                EventSeverity.CRITICAL,
                IncidentStatus.INVESTIGATING,
                "soc.manager",
                now,
                now,
                List.of(new RelatedAlert("ALT-1", "SIEM-1001", "Test Rule", EventSeverity.CRITICAL,
                        "LOGIN_FAILURE", "10.0.0.5", "desc", now)),
                List.of(new TimelineEntry(now, "system", "INCIDENT_CREATED", "created")),
                List.of(new IncidentNote("NT-1", "analyst01", "First note", now))
        );

        repository.save(incident);
        repository.save(incident);

        assertEquals(1, repository.count());

        List<Incident> recent = repository.recent(10);
        assertEquals(1, recent.size());

        Incident loaded = recent.get(0);
        assertEquals("INC-ABC123", loaded.id());
        assertEquals(IncidentStatus.INVESTIGATING, loaded.status());
        assertEquals("soc.manager", loaded.assignedTo());
        assertEquals(1, loaded.relatedAlerts().size());
        assertEquals("ALT-1", loaded.relatedAlerts().get(0).id());
        assertEquals(1, loaded.timeline().size());
        assertEquals("INCIDENT_CREATED", loaded.timeline().get(0).action());
        assertEquals(1, loaded.notes().size());
        assertEquals("First note", loaded.notes().get(0).text());
    }
}