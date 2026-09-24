package com.enterprise.siem.incident.model;

import java.time.Instant;

public record IncidentNote(
        String id,
        String author,
        String text,
        Instant createdAt
) {
}