package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import(AlertRepository.class)
class AlertRepositoryTest {

    @Autowired
    private AlertRepository repository;

    @Test
    void insertsAndReadsAlertsWithWorkflowState() {
        SiemAlert alert = alert("ALT-001");
        repository.insert(alert);
        repository.updateStatus(alert.withStatus(AlertStatus.INVESTIGATING));
        repository.assign("ALT-001", "soc.manager");
        repository.insertNote("ALT-001", new AlertNote("AN-1", "analyst01", "Persisted note", Instant.now()));
        repository.insert(alert);

        assertEquals(1, repository.count());

        List<AlertDetail> recent = repository.recent(10);
        assertEquals(1, recent.size());

        AlertDetail detail = recent.get(0);
        assertEquals(AlertStatus.INVESTIGATING, detail.alert().status());
        assertEquals("soc.manager", detail.assignedTo());
        assertEquals(1, detail.notes().size());
        assertEquals("Persisted note", detail.notes().get(0).text());
    }

    @Test
    void notesAttachToCorrectAlert() {
        repository.insert(alert("ALT-001"));
        repository.insert(alert("ALT-002"));
        repository.insertNote("ALT-002", new AlertNote("AN-9", "analyst02", "Second alert note", Instant.now()));

        List<AlertDetail> recent = repository.recent(10);
        assertTrue(recent.stream()
                .filter(detail -> detail.alert().id().equals("ALT-001"))
                .allMatch(detail -> detail.notes().isEmpty()));
        assertEquals(1, recent.stream()
                .filter(detail -> detail.alert().id().equals("ALT-002"))
                .findFirst().orElseThrow().notes().size());
    }

    private SiemAlert alert(String id) {
        return new SiemAlert(
                id,
                Instant.now(),
                "SIEM-1001",
                "Test Rule",
                "persisted alert",
                EventSeverity.HIGH,
                "LOGIN_FAILURE",
                "EVT-" + id,
                "10.0.0.1",
                "analyst",
                AlertStatus.OPEN
        );
    }
}