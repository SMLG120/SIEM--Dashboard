package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateIncidentRequest(
        @NotBlank(message = "Incident title is required")
        @Size(max = 255)
        String title,
        @Size(max = 4000)
        String description,
        EventSeverity severity
) {
}
