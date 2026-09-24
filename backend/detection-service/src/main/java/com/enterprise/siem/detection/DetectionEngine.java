package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component
public class DetectionEngine {
    private static final List<EventSeverity> RANK = List.of(
            EventSeverity.INFO,
            EventSeverity.LOW,
            EventSeverity.MEDIUM,
            EventSeverity.HIGH,
            EventSeverity.CRITICAL
    );

    private static int rank(EventSeverity severity) {
        int idx = RANK.indexOf(severity);
        return idx < 0 ? 0 : idx;
    }

    public Optional<SiemAlert> evaluate(SecurityEvent event, DetectionRule rule) {
        RuleCondition condition = rule.condition();

        List<String> eventTypes = condition.eventTypes() == null ? List.of() : condition.eventTypes();
        boolean typeMatches = eventTypes.isEmpty() || eventTypes.contains(event.eventType());

        boolean severityMatches = true;
        if (condition.severityMin() != null && !condition.severityMin().isBlank()) {
            EventSeverity min;
            try {
                min = EventSeverity.valueOf(condition.severityMin().trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                min = EventSeverity.INFO;
            }
            severityMatches = rank(event.severity()) >= rank(min);
        }

        boolean categoryMatches = true;
        if (condition.category() != null && !condition.category().isBlank()) {
            categoryMatches = condition.category().equalsIgnoreCase(event.category());
        }

        if (!typeMatches || !severityMatches || !categoryMatches) {
            return Optional.empty();
        }

        EventSeverity alertSeverity = rule.severity() != null ? rule.severity() : event.severity();
        String description = rule.description() != null
                ? rule.description() : "Detection rule " + rule.id() + " matched event " + event.eventType();

        SiemAlert alert = new SiemAlert(
                UUID.randomUUID().toString(),
                Instant.now(),
                rule.id(),
                rule.name(),
                description,
                alertSeverity,
                event.eventType(),
                event.id(),
                event.sourceIp(),
                event.userName(),
                com.enterprise.siem.common.model.AlertStatus.OPEN
        );
        return Optional.of(alert);
    }
}