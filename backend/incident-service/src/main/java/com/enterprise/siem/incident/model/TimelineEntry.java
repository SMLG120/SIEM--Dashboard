package com.enterprise.siem.incident.model;

import java.time.Instant;

public record TimelineEntry(
        Instant occurredAt,
        String actor,
        String action,
        String detail
) {
}