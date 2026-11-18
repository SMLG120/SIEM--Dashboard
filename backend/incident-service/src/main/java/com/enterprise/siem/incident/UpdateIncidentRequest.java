package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.IncidentStatus;
import jakarta.validation.constraints.Size;

public record UpdateIncidentRequest(
        @Size(max = 255)
        String title,
        @Size(max = 4000)
        String description,
        EventSeverity severity,
        IncidentStatus status,
        @Size(max = 128)
        @jakarta.validation.constraints.Pattern(regexp = "^[A-Za-z0-9._@-]*$", message = "assignedTo must be a username")
        String assignedTo
) {
}
