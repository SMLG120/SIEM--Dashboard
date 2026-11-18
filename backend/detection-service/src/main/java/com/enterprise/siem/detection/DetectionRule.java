package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.MitreTechnique;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * A detection rule. {@code id} is stable forever; {@code version} increases whenever the logic changes
 * (and on every enable/disable/severity change applied at runtime), and is stamped on each alert.
 *
 * @param suppressionSeconds for THRESHOLD/SEQUENCE rules: after firing for a group key, don't fire
 *                           again for that key until this many seconds of event time have passed
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record DetectionRule(
        String id,
        Integer version,
        String name,
        String description,
        EventSeverity severity,
        boolean enabled,
        RuleType type,
        RuleCondition condition,
        ThresholdSpec threshold,
        SequenceSpec sequence,
        Integer suppressionSeconds,
        List<MitreTechnique> mitre,
        List<String> falsePositives,
        RuleExamples examples
) {
    public DetectionRule {
        version = version == null || version < 1 ? 1 : version;
        type = type == null ? RuleType.SINGLE : type;
        condition = condition == null ? new RuleCondition(null, null, null) : condition;
        mitre = mitre == null ? List.of() : List.copyOf(mitre);
        falsePositives = falsePositives == null ? List.of() : List.copyOf(falsePositives);
        examples = examples == null ? new RuleExamples(null, null) : examples;
    }

    /** v1 shape (single-event rule), kept for existing callers and tests. */
    public DetectionRule(String id, String name, String description, EventSeverity severity, boolean enabled,
                         RuleCondition condition) {
        this(id, 1, name, description, severity, enabled, RuleType.SINGLE, condition, null, null, null,
                null, null, null);
    }

    public DetectionRule withEnabled(boolean value) {
        return new DetectionRule(id, version + 1, name, description, severity, value, type, condition, threshold,
                sequence, suppressionSeconds, mitre, falsePositives, examples);
    }

    public DetectionRule withSeverity(EventSeverity value) {
        return new DetectionRule(id, version + 1, name, description, value, enabled, type, condition, threshold,
                sequence, suppressionSeconds, mitre, falsePositives, examples);
    }

    public int effectiveSuppressionSeconds() {
        if (suppressionSeconds != null && suppressionSeconds >= 0) {
            return suppressionSeconds;
        }
        int window = type == RuleType.THRESHOLD && threshold != null ? threshold.windowSeconds()
                : type == RuleType.SEQUENCE && sequence != null ? sequence.windowSeconds() : 0;
        return window;
    }
}
