package com.enterprise.siem.incident.model;

import com.enterprise.siem.common.model.EventSeverity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record Incident(
        String id,
        String title,
        String description,
        EventSeverity severity,
        IncidentStatus status,
        String assignedTo,
        Instant createdAt,
        Instant updatedAt,
        List<RelatedAlert> relatedAlerts,
        List<TimelineEntry> timeline,
        List<IncidentNote> notes
) {
    public static Incident create(String id, String title, String description, EventSeverity severity) {
        Instant now = Instant.now();
        return new Incident(
                id,
                title,
                description,
                severity,
                IncidentStatus.OPEN,
                null,
                now,
                now,
                new ArrayList<>(),
                new ArrayList<>(),
                new ArrayList<>()
        );
    }

    public Incident appendAlert(RelatedAlert alert) {
        List<RelatedAlert> alerts = append(this.relatedAlerts, alert);
        return new Incident(id, title, description, severity, status, assignedTo, createdAt, Instant.now(), alerts, timeline, notes);
    }

    public Incident appendTimeline(TimelineEntry entry) {
        List<TimelineEntry> entries = append(this.timeline, entry);
        return new Incident(id, title, description, severity, status, assignedTo, createdAt, Instant.now(), relatedAlerts, entries, notes);
    }

    public Incident appendNote(IncidentNote note) {
        List<IncidentNote> allNotes = append(this.notes, note);
        return new Incident(id, title, description, severity, status, assignedTo, createdAt, Instant.now(), relatedAlerts, timeline, allNotes);
    }

    public Incident withStatus(IncidentStatus newStatus) {
        return new Incident(id, title, description, severity, newStatus, assignedTo, createdAt, Instant.now(), relatedAlerts, timeline, notes);
    }

    public Incident withAssignedTo(String analyst) {
        return new Incident(id, title, description, severity, status, analyst, createdAt, Instant.now(), relatedAlerts, timeline, notes);
    }

    public Incident withSeverity(EventSeverity newSeverity) {
        return new Incident(id, title, description, newSeverity, status, assignedTo, createdAt, Instant.now(), relatedAlerts, timeline, notes);
    }

    public Incident withTitle(String newTitle) {
        return new Incident(id, newTitle, description, severity, status, assignedTo, createdAt, Instant.now(), relatedAlerts, timeline, notes);
    }

    public Incident withDescription(String newDescription) {
        return new Incident(id, title, newDescription, severity, status, assignedTo, createdAt, Instant.now(), relatedAlerts, timeline, notes);
    }

    public boolean containsAlert(String alertId) {
        return relatedAlerts.stream().anyMatch(alert -> alert.id().equals(alertId));
    }

    public boolean isActive() {
        return status == IncidentStatus.OPEN
                || status == IncidentStatus.INVESTIGATING
                || status == IncidentStatus.CONTAINED;
    }

    private static <T> List<T> append(List<T> current, T item) {
        return Stream.concat(current.stream(), Stream.of(item)).collect(Collectors.toCollection(ArrayList::new));
    }
}