package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Evaluates a {@link RuleCondition} against one event and explains which clauses matched.
 * Pure and stateless; safe to share.
 */
final class ConditionMatcher {
    private ConditionMatcher() {
    }

    /** @return the matched clauses as readable strings, or empty if any clause fails. */
    static Optional<List<String>> match(RuleCondition condition, SecurityEvent event) {
        List<String> matched = new ArrayList<>();

        if (!condition.eventTypes().isEmpty()) {
            if (event.eventType() == null || condition.eventTypes().stream().noneMatch(t -> t.equalsIgnoreCase(event.eventType()))) {
                return Optional.empty();
            }
            matched.add("eventType " + event.eventType() + " in " + condition.eventTypes());
        }

        if (condition.severityMin() != null && !condition.severityMin().isBlank()) {
            EventSeverity min = parseSeverity(condition.severityMin());
            if (event.severity() == null || event.severity().ordinal() < min.ordinal()) {
                return Optional.empty();
            }
            matched.add("severity " + event.severity() + " >= " + min);
        }

        if (condition.category() != null && !condition.category().isBlank()) {
            if (!condition.category().equalsIgnoreCase(event.category())) {
                return Optional.empty();
            }
            matched.add("category = " + condition.category().toUpperCase(Locale.ROOT));
        }

        if (!condition.messageContainsAny().isEmpty()) {
            Optional<String> hit = containsAny(event.message(), condition.messageContainsAny());
            if (hit.isEmpty()) {
                return Optional.empty();
            }
            matched.add("message contains \"" + hit.get() + "\"");
        }

        for (Map.Entry<String, List<String>> clause : condition.attributeContainsAny().entrySet()) {
            Optional<String> hit = containsAny(event.attribute(clause.getKey()), clause.getValue());
            if (hit.isEmpty()) {
                return Optional.empty();
            }
            matched.add(clause.getKey() + " contains \"" + hit.get() + "\"");
        }

        for (Map.Entry<String, List<String>> clause : condition.attributeEquals().entrySet()) {
            String value = event.attribute(clause.getKey());
            if (value == null || clause.getValue().stream().noneMatch(v -> v.equalsIgnoreCase(value))) {
                return Optional.empty();
            }
            matched.add(clause.getKey() + " = " + value);
        }

        if (!condition.destinationPorts().isEmpty()) {
            if (event.destinationPort() == null || !condition.destinationPorts().contains(event.destinationPort())) {
                return Optional.empty();
            }
            matched.add("destinationPort " + event.destinationPort() + " in " + condition.destinationPorts());
        }

        if (condition.externalDestination() != null) {
            Boolean external = isPublic(event.destinationIp());
            if (external == null || external != condition.externalDestination()) {
                return Optional.empty();
            }
            matched.add("destination " + event.destinationIp() + (external ? " is external" : " is internal"));
        }

        if (matched.isEmpty()) {
            matched.add("any event");
        }
        return Optional.of(matched);
    }

    static EventSeverity parseSeverity(String value) {
        try {
            return EventSeverity.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return EventSeverity.INFO; // historical behaviour: an unknown minimum matches everything
        }
    }

    private static Optional<String> containsAny(String haystack, List<String> needles) {
        if (haystack == null) {
            return Optional.empty();
        }
        String lower = haystack.toLowerCase(Locale.ROOT);
        return needles.stream().filter(n -> lower.contains(n.toLowerCase(Locale.ROOT))).findFirst();
    }

    /**
     * @return true for public addresses, false for private/loopback/link-local, null if not a literal IP.
     * Only literals are passed to InetAddress (validated at ingestion), so no DNS lookup happens.
     */
    static Boolean isPublic(String ip) {
        if (ip == null || ip.isBlank() || !ip.matches("^[0-9A-Fa-f:.]+$")) {
            return null;
        }
        try {
            InetAddress address = InetAddress.getByName(ip);
            boolean internal = address.isSiteLocalAddress() || address.isLoopbackAddress()
                    || address.isLinkLocalAddress() || address.isAnyLocalAddress()
                    || isUniqueLocalV6(address) || isCarrierGradeNat(address);
            return !internal;
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean isUniqueLocalV6(InetAddress address) {
        byte[] b = address.getAddress();
        return b.length == 16 && (b[0] & 0xFE) == 0xFC; // fc00::/7
    }

    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] b = address.getAddress();
        return b.length == 4 && (b[0] & 0xFF) == 100 && (b[1] & 0xC0) == 64; // 100.64.0.0/10
    }
}
