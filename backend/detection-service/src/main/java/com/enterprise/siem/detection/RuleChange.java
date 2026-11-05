package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleChange(
        @JsonProperty("ruleId") String ruleId,
        @JsonProperty("action") RuleChangeAction action,
        @JsonProperty("severity") EventSeverity severity,
        @JsonProperty("actor") String actor,
        @JsonProperty("changedAt") Instant changedAt
) {
    @JsonCreator
    public RuleChange {
    }

    public RuleChange(String ruleId, RuleChangeAction action, EventSeverity severity) {
        this(ruleId, action, severity, null, null);
    }
}
