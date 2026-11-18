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
        @JsonProperty("changedAt") Instant changedAt,
        @JsonProperty("resultingVersion") Integer resultingVersion,
        @JsonProperty("changeId") String changeId
) {
    /**
     * Records written before changeId existed get a stable ID derived from their content, so replaying
     * them twice is still recognised as the same change.
     */
    @JsonCreator
    public RuleChange {
        if (changeId == null || changeId.isBlank()) {
            changeId = com.enterprise.siem.common.ids.DeterministicIds.of("siem-rule-change", ruleId,
                    String.valueOf(action), String.valueOf(severity), actor, String.valueOf(changedAt));
        }
    }

    public RuleChange(String ruleId, RuleChangeAction action, EventSeverity severity, String actor, Instant changedAt) {
        this(ruleId, action, severity, actor, changedAt, null, java.util.UUID.randomUUID().toString());
    }

    public RuleChange(String ruleId, RuleChangeAction action, EventSeverity severity) {
        this(ruleId, action, severity, null, null, null, java.util.UUID.randomUUID().toString());
    }

    RuleChange withVersion(int version) {
        return new RuleChange(ruleId, action, severity, actor, changedAt, version, changeId);
    }
}
