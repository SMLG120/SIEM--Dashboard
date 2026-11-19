package com.enterprise.siem.detection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Per-event filter. Every non-empty clause must hold (AND); list values inside a clause are
 * alternatives (OR). String comparisons are case-insensitive.
 *
 * @param eventTypes          event type is one of these
 * @param category            event category equals this
 * @param severityMin         event severity is at least this
 * @param messageContainsAny  message contains at least one of these substrings
 * @param attributeContainsAny for each attribute name, its value contains at least one of the substrings
 * @param attributeEquals     for each attribute name, its value equals one of the listed values
 * @param destinationPorts    destination port is one of these
 * @param externalDestination true: destination IP must be public; false: must be private/loopback
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RuleCondition(
        List<String> eventTypes,
        String category,
        String severityMin,
        List<String> messageContainsAny,
        Map<String, List<String>> attributeContainsAny,
        Map<String, List<String>> attributeEquals,
        List<Integer> destinationPorts,
        Boolean externalDestination
) {
    public RuleCondition {
        eventTypes = eventTypes == null ? List.of() : List.copyOf(eventTypes);
        messageContainsAny = messageContainsAny == null ? List.of() : List.copyOf(messageContainsAny);
        attributeContainsAny = attributeContainsAny == null ? Map.of() : Map.copyOf(attributeContainsAny);
        attributeEquals = attributeEquals == null ? Map.of() : Map.copyOf(attributeEquals);
        destinationPorts = destinationPorts == null ? List.of() : List.copyOf(destinationPorts);
    }

    /** v1 shape used by the original seven rules and existing tests. */
    public RuleCondition(List<String> eventTypes, String category, String severityMin) {
        this(eventTypes, category, severityMin, null, null, null, null, null);
    }
}
