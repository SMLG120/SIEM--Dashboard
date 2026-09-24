package com.enterprise.siem.incident;

import java.time.Instant;

public record IncidentEvent(
        String incidentId,
        String title,
        String action,
        Instant at
) {
}