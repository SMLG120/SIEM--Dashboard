package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LinkAlertRequest(
        @NotBlank(message = "alertId is required")
        @Size(max = 64)
        String alertId,
        @Size(max = 64)
        String ruleId,
        @Size(max = 255)
        String ruleName,
        @Size(max = 64)
        String eventType,
        EventSeverity severity,
        @Size(max = 64)
        String sourceIp,
        @Size(max = 2000)
        String description
) {
}
