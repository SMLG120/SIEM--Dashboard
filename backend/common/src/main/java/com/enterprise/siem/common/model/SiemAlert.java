package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;

/**
 * The {@code siem.alerts} contract. Same evolution rules as {@link SecurityEvent}: v2 adds
 * {@code ruleVersion}, {@code mitre} and {@code evidence}; v1 records read with those empty.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SiemAlert(
        @JsonProperty("id") String id,
        @JsonProperty("createdAt") Instant createdAt,
        @JsonProperty("ruleId") String ruleId,
        @JsonProperty("ruleName") String ruleName,
        @JsonProperty("description") String description,
        @JsonProperty("severity") EventSeverity severity,
        @JsonProperty("eventType") String eventType,
        @JsonProperty("eventId") String eventId,
        @JsonProperty("sourceIp") String sourceIp,
        @JsonProperty("userName") String userName,
        @JsonProperty("status") AlertStatus status,
        @JsonProperty("ruleVersion") Integer ruleVersion,
        @JsonProperty("mitre") List<MitreTechnique> mitre,
        @JsonProperty("evidence") AlertEvidence evidence,
        @JsonProperty("schemaVersion") Integer schemaVersion
) {
    public static final int CURRENT_SCHEMA_VERSION = 2;

    @JsonCreator
    public SiemAlert {
        mitre = mitre == null ? List.of() : List.copyOf(mitre);
        schemaVersion = schemaVersion == null ? 1 : schemaVersion;
    }

    /** v1 shape, kept so existing callers compile unchanged. */
    public SiemAlert(String id, Instant createdAt, String ruleId, String ruleName, String description,
                     EventSeverity severity, String eventType, String eventId, String sourceIp, String userName,
                     AlertStatus status) {
        this(id, createdAt, ruleId, ruleName, description, severity, eventType, eventId, sourceIp, userName, status,
                null, List.of(), null, 1);
    }

    public SiemAlert withStatus(AlertStatus newStatus) {
        return new SiemAlert(id, createdAt, ruleId, ruleName, description, severity, eventType, eventId, sourceIp,
                userName, newStatus, ruleVersion, mitre, evidence, schemaVersion);
    }
}
