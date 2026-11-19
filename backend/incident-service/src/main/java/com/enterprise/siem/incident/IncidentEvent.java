package com.enterprise.siem.incident;

import java.time.Instant;

/**
 * One change to an incident, published on {@code siem.incidents} after commit. v2 adds the actor and
 * detail of the timeline entry so the audit service can attribute every change.
 */
public record IncidentEvent(
        String incidentId,
        String title,
        String action,
        Instant at,
        String actor,
        String detail
) {
    public IncidentEvent(String incidentId, String title, String action, Instant at) {
        this(incidentId, title, action, at, null, null);
    }
}
