package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;

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
        @JsonProperty("schemaVersion") Integer schemaVersion,
        @JsonProperty("attributes") Map<String, String> attributes
) {
    /**
     * v1: the original fields. v2: adds {@code attributes}, a bounded map of source-specific
     * observables (for example {@code bytesOut}, {@code commandLine}, {@code fileHash}, {@code group}).
     */
    public static final int CURRENT_SCHEMA_VERSION = 2;

    @JsonCreator
    public SecurityEvent {
        schemaVersion = schemaVersion == null ? 1 : schemaVersion;
        attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
    }

    public SecurityEvent(String id, Instant timestamp, String eventType, EventSeverity severity, String category,
                         String sourceIp, String sourceHost, String destinationIp, Integer destinationPort,
                         String userName, String message, Integer schemaVersion) {
        this(id, timestamp, eventType, severity, category, sourceIp, sourceHost, destinationIp, destinationPort,
                userName, message, schemaVersion, Map.of());
    }

    public String attribute(String name) {
        return attributes.get(name);
    }

    /** Pre-versioning constructor, kept so existing callers compile unchanged. */
    public SecurityEvent(String id, Instant timestamp, String eventType, EventSeverity severity, String category,
                         String sourceIp, String sourceHost, String destinationIp, Integer destinationPort,
                         String userName, String message) {
        this(id, timestamp, eventType, severity, category, sourceIp, sourceHost, destinationIp, destinationPort,
                userName, message, 1, Map.of());
    }
}
