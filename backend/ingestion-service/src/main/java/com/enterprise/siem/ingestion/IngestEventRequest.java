package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.validation.IpAddress;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Map;

/**
 * Inbound event schema (v2: adds attributes). Unknown JSON properties are rejected by the controller's message
 * converter configuration, so typos in field names fail loudly instead of being dropped.
 *
 * @param sourceEventId optional client-side identifier. When present, retries with the same value
 *                      from the same client produce the same event ID and are stored once.
 * @param occurredAt    optional event time; defaults to the time the platform received the event.
 * @param attributes    optional source-specific fields used by detection rules (e.g. bytesOut, fileHash).
 *                      At most 32 entries; keys are identifiers of up to 64 chars, values up to 512 chars.
 */
public record IngestEventRequest(
        @NotBlank(message = "eventType is required")
        @Size(max = 64)
        @Pattern(regexp = "^[A-Za-z0-9_.:-]+$", message = "eventType may contain only letters, digits and _ . : -")
        String eventType,
        @NotNull(message = "severity is required")
        EventSeverity severity,
        @Size(max = 64)
        @Pattern(regexp = "^[A-Za-z0-9_.:-]*$", message = "category may contain only letters, digits and _ . : -")
        String category,
        @IpAddress
        @Size(max = 64)
        String sourceIp,
        @Size(max = 128)
        String sourceHost,
        @IpAddress
        @Size(max = 64)
        String destinationIp,
        @Min(0)
        @Max(65535)
        Integer destinationPort,
        @Size(max = 128)
        String userName,
        @Size(max = 2000)
        String message,
        @Size(max = 128)
        @Pattern(regexp = "^[A-Za-z0-9_.:-]*$", message = "sourceEventId may contain only letters, digits and _ . : -")
        String sourceEventId,
        Instant occurredAt,
        @Size(max = 32, message = "at most 32 attributes")
        Map<@Pattern(regexp = "^[A-Za-z][A-Za-z0-9_.]{0,63}$", message = "attribute keys must be identifiers") String,
                @NotNull @Size(max = 512) String> attributes
) {
    public IngestEventRequest(String eventType, EventSeverity severity, String category, String sourceIp,
                              String sourceHost, String destinationIp, Integer destinationPort, String userName,
                              String message, String sourceEventId, Instant occurredAt) {
        this(eventType, severity, category, sourceIp, sourceHost, destinationIp, destinationPort, userName, message,
                sourceEventId, occurredAt, null);
    }

    /** Pre-v2 shape, kept for existing callers and tests. */
    public IngestEventRequest(String eventType, EventSeverity severity, String category, String sourceIp,
                              String sourceHost, String destinationIp, Integer destinationPort, String userName,
                              String message) {
        this(eventType, severity, category, sourceIp, sourceHost, destinationIp, destinationPort, userName, message,
                null, null);
    }

    public String effectiveCategory() {
        return category == null || category.isBlank() ? "GENERAL" : category.toUpperCase();
    }

    public String normalizedEventType() {
        return eventType.trim().toUpperCase();
    }
}
