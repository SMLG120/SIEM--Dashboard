package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record DetectionRule(
        String id,
        String name,
        String description,
        EventSeverity severity,
        boolean enabled,
        RuleCondition condition
) {
}