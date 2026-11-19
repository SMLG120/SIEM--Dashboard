package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;

import java.time.Instant;

/** One immutable line of an alert's investigation history (stored append-only). */
public record AlertHistoryEntry(
        String alertId,
        String action,
        AlertStatus fromStatus,
        AlertStatus toStatus,
        String actor,
        String detail,
        Instant occurredAt
) {
}
