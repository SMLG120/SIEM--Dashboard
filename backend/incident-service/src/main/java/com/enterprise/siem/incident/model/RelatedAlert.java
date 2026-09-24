package com.enterprise.siem.incident.model;

import com.enterprise.siem.common.model.EventSeverity;

import java.time.Instant;

public record RelatedAlert(
        String id,
        String ruleId,
        String ruleName,
        EventSeverity severity,
        String eventType,
        String sourceIp,
        String description,
        Instant createdAt
) {
}