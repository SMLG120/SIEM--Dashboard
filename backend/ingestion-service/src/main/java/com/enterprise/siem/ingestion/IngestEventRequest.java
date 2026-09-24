package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record IngestEventRequest(
        @NotBlank(message = "eventType is required")
        @Size(max = 100)
        String eventType,
        @NotNull(message = "severity is required")
        EventSeverity severity,
        @Size(max = 80)
        String category,
        @Size(max = 64)
        String sourceIp,
        @Size(max = 128)
        String sourceHost,
        @Size(max = 64)
        String destinationIp,
        Integer destinationPort,
        @Size(max = 128)
        String userName,
        @Size(max = 2000)
        String message
) {
    public String effectiveCategory() {
        return category == null || category.isBlank() ? "GENERAL" : category.toUpperCase();
    }
}