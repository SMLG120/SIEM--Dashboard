package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.IncidentStatus;

public record UpdateIncidentRequest(
        String title,
        String description,
        EventSeverity severity,
        IncidentStatus status,
        String assignedTo
) {
}