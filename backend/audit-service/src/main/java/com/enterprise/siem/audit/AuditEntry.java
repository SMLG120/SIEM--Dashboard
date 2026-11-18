package com.enterprise.siem.audit;

import java.time.Instant;

public record AuditEntry(
        long id,
        Instant occurredAt,
        String actor,
        String action,
        String resourceType,
        String resourceId,
        String detail
) {
}
