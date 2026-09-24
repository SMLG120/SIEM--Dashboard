package com.enterprise.siem.detection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleCondition(
        List<String> eventTypes,
        String category,
        String severityMin
) {
    public RuleCondition {
        eventTypes = eventTypes == null ? List.of() : List.copyOf(eventTypes);
    }
}