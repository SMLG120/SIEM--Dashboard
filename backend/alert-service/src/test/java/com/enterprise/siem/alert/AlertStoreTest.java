package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlertStoreTest {

    private static SiemAlert alert(String id) {
        return new SiemAlert(
                id,
                Instant.now(),
                "SIEM-1001",
                "Test Rule",
                "desc",
                EventSeverity.HIGH,
                "LOGIN_FAILURE",
                "EVT-" + id,
                "10.0.0.1",
                "analyst",
                AlertStatus.OPEN
        );
    }

    @Test
    void retainsAssignmentAndNotesAcrossStatusUpdates() {
        AlertStore store = new AlertStore();
        store.add(alert("a1"));

        store.assign("a1", "soc.manager");
        store.addNote("a1", "analyst01", "Escalating to incident team");
        AlertDetail detail = store.workflow("a1").orElseThrow();

        assertEquals("soc.manager", detail.assignedTo());
        assertEquals(1, detail.notes().size());
        assertEquals("Escalating to incident team", detail.notes().get(0).text());
        assertEquals("analyst01", detail.notes().get(0).author());
    }

    @Test
    void transitionsStatus() {
        AlertStore store = new AlertStore();
        store.add(alert("a1"));

        assertEquals(AlertStatus.INVESTIGATING, store.updateStatus("a1", AlertStatus.INVESTIGATING)
                .orElseThrow().status());
        assertEquals(AlertStatus.RESOLVED, store.updateStatus("a1", AlertStatus.RESOLVED)
                .orElseThrow().status());
        assertTrue(store.byId("missing").isEmpty());
    }

    @Test
    void rejectsTransitionFromDisallowedStatus() {
        AlertStore store = new AlertStore();
        store.add(alert("a1"));

        assertThrows(AlertStore.InvalidTransitionException.class, () ->
                store.transition("a1", EnumSet.of(AlertStatus.RESOLVED), AlertStatus.OPEN, ignored -> {
                }));
        assertEquals(AlertStatus.OPEN, store.byId("a1").orElseThrow().status());
    }

    @Test
    void failedPersistLeavesStoreUnchanged() {
        AlertStore store = new AlertStore();
        store.add(alert("a1"));

        assertThrows(IllegalStateException.class, () ->
                store.transition("a1", EnumSet.allOf(AlertStatus.class), AlertStatus.RESOLVED, ignored -> {
                    throw new IllegalStateException("db down");
                }));
        assertThrows(IllegalStateException.class, () ->
                store.addNote("a1", "analyst", "note", ignored -> {
                    throw new IllegalStateException("db down");
                }));

        assertEquals(AlertStatus.OPEN, store.byId("a1").orElseThrow().status());
        assertTrue(store.workflow("a1").orElseThrow().notes().isEmpty());
    }

    @Test
    void redeliveredAlertIsNotDuplicated() {
        AlertStore store = new AlertStore();
        store.add(alert("a1"));
        store.add(alert("a1"));

        assertEquals(1, store.all().size());
    }
}
