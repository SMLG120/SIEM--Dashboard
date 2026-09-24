package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

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
        @JsonProperty("status") AlertStatus status
) {
    @JsonCreator
    public SiemAlert {
    }

    public SiemAlert withStatus(AlertStatus newStatus) {
        return new SiemAlert(
                id,
                createdAt,
                ruleId,
                ruleName,
                description,
                severity,
                eventType,
                eventId,
                sourceIp,
                userName,
                newStatus
        );
    }
}