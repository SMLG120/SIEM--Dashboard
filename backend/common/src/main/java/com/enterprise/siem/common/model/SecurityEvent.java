package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

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
        @JsonProperty("message") String message
) {
    @JsonCreator
    public SecurityEvent {
    }
}