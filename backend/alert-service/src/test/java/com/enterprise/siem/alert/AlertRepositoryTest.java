package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AlertRepository.class, AlertService.class})
@ImportAutoConfiguration(JacksonAutoConfiguration.class)
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

    @Autowired
    private AlertService service;

    @Autowired
    private org.springframework.jdbc.core.simple.JdbcClient jdbc;

    @Test
    void v2FieldsRoundTripThroughTheDatabase() {
        SiemAlert v2 = new SiemAlert("ALT-V2", Instant.parse("2026-01-01T00:00:00Z"), "SIEM-1008", "Brute", "d",
                EventSeverity.HIGH, "LOGIN_FAILURE", "e5", "1.2.3.4", "bob", AlertStatus.OPEN, 4,
                List.of(new com.enterprise.siem.common.model.MitreTechnique("Credential Access", "T1110.001", "Password Guessing")),
                new com.enterprise.siem.common.model.AlertEvidence("THRESHOLD", List.of("count = 5 >= 5"),
                        List.of("e1", "e5"), 5, "sourceIp=1.2.3.4", 300, Instant.parse("2025-12-31T23:58:00Z"),
                        Instant.parse("2026-01-01T00:00:00Z")),
                SiemAlert.CURRENT_SCHEMA_VERSION);
        assertTrue(repository.insert(v2));
        assertTrue(!repository.insert(v2), "redelivery is a no-op");

        SiemAlert read = repository.findById("ALT-V2").orElseThrow();
        assertEquals(4, read.ruleVersion());
        assertEquals("T1110.001", read.mitre().getFirst().techniqueId());
        assertEquals(List.of("e1", "e5"), read.evidence().eventIds());
        assertEquals("sourceIp=1.2.3.4", read.evidence().groupKey());
    }

    @Test
    void workflowWritesHistoryAndRejectsInvalidTransitions() {
        service.record(alert("ALT-WF"));
        service.transition("ALT-WF", AlertStatus.INVESTIGATING, "analyst01", null);
        service.assign("ALT-WF", "analyst02", "soc.manager");
        service.addNote("ALT-WF", "analyst02", "checked VPN logs");
        service.transition("ALT-WF", AlertStatus.RESOLVED, "analyst02", null);
        org.junit.jupiter.api.Assertions.assertThrows(AlertService.InvalidTransitionException.class,
                () -> service.transition("ALT-WF", AlertStatus.ACKNOWLEDGED, "analyst01", null));

        List<AlertHistoryEntry> history = repository.history("ALT-WF");
        assertEquals(List.of("CREATED", "INVESTIGATING", "ASSIGNED", "NOTE_ADDED", "RESOLVED"),
                history.stream().map(AlertHistoryEntry::action).toList());
        assertEquals("analyst01", history.get(1).actor());
        assertEquals(AlertStatus.OPEN, history.get(1).fromStatus());
        assertEquals(AlertStatus.RESOLVED, repository.findById("ALT-WF").orElseThrow().status());
    }

    @Test
    void historyIsAppendOnlyInTheDatabase() {
        service.record(alert("ALT-AO"));
        org.junit.jupiter.api.Assertions.assertThrows(Exception.class,
                () -> jdbc.sql("UPDATE siem_alert_history SET actor = 'mallory' WHERE alert_id = 'ALT-AO'").update());
    }

    @Test
    void searchFiltersAndSortsBySeverityRank() {
        Instant now = Instant.now();
        for (EventSeverity sev : List.of(EventSeverity.LOW, EventSeverity.CRITICAL, EventSeverity.MEDIUM)) {
            repository.insert(new SiemAlert("S-" + sev, now, "SIEM-9999", "r", "d", sev, "X", "e", "9.9.9.9", "u",
                    AlertStatus.OPEN));
        }
        AlertRepository.Page page = repository.search(new AlertRepository.AlertQuery(List.of(AlertStatus.OPEN), List.of(),
                "SIEM-9999", null, null, null, AlertRepository.Sort.SEVERITY, 0, 2));
        assertEquals(3, page.total());
        assertEquals(List.of(EventSeverity.CRITICAL, EventSeverity.MEDIUM),
                page.items().stream().map(SiemAlert::severity).toList());
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