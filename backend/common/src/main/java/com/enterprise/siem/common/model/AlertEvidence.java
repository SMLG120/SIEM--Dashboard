package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;
import java.util.List;

/**
 * Why an alert fired: the rule logic that matched and the events that contributed.
 *
 * @param matchedConditions human-readable conditions that were satisfied, e.g. "eventType in [LOGIN_FAILURE]"
 * @param eventIds          contributing event IDs, oldest first (capped; see {@code eventCount})
 * @param eventCount        total number of contributing events (may exceed {@code eventIds.size()})
 * @param groupKey          correlation key for threshold/sequence rules, e.g. "sourceIp=10.0.0.5"
 * @param windowSeconds     correlation window for threshold/sequence rules
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AlertEvidence(
        String ruleType,
        List<String> matchedConditions,
        List<String> eventIds,
        Integer eventCount,
        String groupKey,
        Integer windowSeconds,
        Instant firstSeen,
        Instant lastSeen
) {
    public static final int MAX_EVENT_IDS = 50;

    public AlertEvidence {
        matchedConditions = matchedConditions == null ? List.of() : List.copyOf(matchedConditions);
        eventIds = eventIds == null ? List.of() : List.copyOf(eventIds);
    }
}
