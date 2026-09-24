package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;

public record CreateIncidentRequest(
        String title,
        String description,
        EventSeverity severity
) {
}