package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * The {@code siem.events} contract.
 *
 * <p>Versioning rules: fields are only ever added, never renamed or retyped, and every consumer
 * ignores unknown fields. {@code schemaVersion} is bumped when a new field changes how a record
 * should be interpreted, so old consumers keep working and new consumers can branch on it.
 * Records written before versioning existed carry no version and are read as version 1.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SecurityEvent(
        @JsonProperty("id") String id,
        @JsonProperty("timestamp") Instant timestamp,
        @JsonProperty("eventType") String eventType,
        @JsonProperty("severity") EventSeverity severity,
        @JsonProperty("category") String category,
        @JsonProperty("sourceIp") String sourceIp,
        @JsonProperty("sourceHost") String sourceHost,
        @JsonProperty("destinationIp") String destinationIp,
        @JsonProperty("destinationPort") Integer destinationPort,
        @JsonProperty("userName") String userName,
        @JsonProperty("message") String message,
        @JsonProperty("schemaVersion") Integer schemaVersion
) {
    public static final int CURRENT_SCHEMA_VERSION = 1;

    @JsonCreator
    public SecurityEvent {
        schemaVersion = schemaVersion == null ? 1 : schemaVersion;
    }

    /** Pre-versioning constructor, kept so existing callers compile unchanged. */
    public SecurityEvent(String id, Instant timestamp, String eventType, EventSeverity severity, String category,
                         String sourceIp, String sourceHost, String destinationIp, Integer destinationPort,
                         String userName, String message) {
        this(id, timestamp, eventType, severity, category, sourceIp, sourceHost, destinationIp, destinationPort,
                userName, message, CURRENT_SCHEMA_VERSION);
    }
}
