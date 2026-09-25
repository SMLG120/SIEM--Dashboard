package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleChange(
        @JsonProperty("ruleId") String ruleId,
        @JsonProperty("action") RuleChangeAction action,
        @JsonProperty("severity") EventSeverity severity
) {
    @JsonCreator
    public RuleChange {
    }
}