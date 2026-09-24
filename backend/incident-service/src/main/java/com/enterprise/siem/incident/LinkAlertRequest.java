package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;

public record LinkAlertRequest(
        String alertId,
        String ruleId,
        String ruleName,
        String eventType,
        EventSeverity severity,
        String sourceIp,
        String description
) {
}