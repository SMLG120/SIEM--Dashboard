package com.enterprise.siem.detection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Ordered steps for one correlation key within a window, e.g. "at least 3 LOGIN_FAILURE, then a
 * LOGIN_SUCCESS for the same user within 10 minutes".
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SequenceSpec(List<String> groupBy, int windowSeconds, List<Step> steps) {
    public SequenceSpec {
        groupBy = groupBy == null ? List.of() : List.copyOf(groupBy);
        steps = steps == null ? List.of() : List.copyOf(steps);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Step(String name, RuleCondition condition, Integer minCount) {
        public int requiredCount() {
            return minCount == null || minCount < 1 ? 1 : minCount;
        }
    }
}
