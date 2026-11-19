package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.SecurityEvent;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Synthetic example events shipped with each rule. {@code match} is a sequence that must fire the
 * rule exactly once; {@code noMatch} is a sequence that must not fire it. Unit tests replay both.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleExamples(List<SecurityEvent> match, List<SecurityEvent> noMatch) {
    public RuleExamples {
        match = match == null ? List.of() : List.copyOf(match);
        noMatch = noMatch == null ? List.of() : List.copyOf(noMatch);
    }
}
