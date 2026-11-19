package com.enterprise.siem.detection;

import org.springframework.stereotype.Repository;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Rule definitions come from the packaged {@code detection-rules.json}; runtime changes (enable,
 * disable, severity) arrive through {@code siem.rules} and are replayed on startup. Every applied
 * change increments the rule's version and is kept in {@link #history(String)}.
 */
@Repository
public class DetectionRuleRepository {
    static final int MAX_HISTORY_PER_RULE = 200;

    private final List<DetectionRule> rules = new CopyOnWriteArrayList<>();
    private final Map<String, List<RuleChange>> history = new ConcurrentHashMap<>();
    private final Set<String> appliedChangeIds = ConcurrentHashMap.newKeySet();

    public DetectionRuleRepository(ObjectMapper objectMapper) {
        try (InputStream in = getClass().getResourceAsStream("/detection-rules.json")) {
            List<DetectionRule> loaded = objectMapper.readValue(in, new TypeReference<>() {
            });
            validate(loaded);
            this.rules.addAll(loaded);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load detection rules", e);
        }
    }

    static void validate(List<DetectionRule> loaded) {
        Set<String> ids = new HashSet<>();
        for (DetectionRule rule : loaded) {
            validate(rule);
            if (!ids.add(rule.id())) {
                throw new IllegalStateException("Duplicate rule id " + rule.id());
            }
        }
    }

    /** Rejects structurally invalid rules (also used by the rule tester for ad-hoc rules). */
    static void validate(DetectionRule rule) {
        if (rule.id() == null || !rule.id().matches("^[A-Z0-9-]{3,32}$")) {
            throw new IllegalArgumentException("Rule id must be 3-32 chars of A-Z, 0-9 and '-'");
        }
        if (rule.name() == null || rule.name().isBlank()) {
            throw new IllegalArgumentException(rule.id() + ": name is required");
        }
        switch (rule.type()) {
            case THRESHOLD -> {
                ThresholdSpec t = rule.threshold();
                if (t == null || t.windowSeconds() < 1 || t.windowSeconds() > 86_400) {
                    throw new IllegalArgumentException(rule.id() + ": threshold.windowSeconds must be 1..86400");
                }
                if (t.distinctField() == null && t.sumAttribute() == null && (t.count() == null || t.count() < 1)) {
                    throw new IllegalArgumentException(rule.id() + ": threshold needs count, distinctField or sumAttribute");
                }
                if ((t.distinctField() != null || t.sumAttribute() != null) && (t.minimum() == null || t.minimum() < 1)) {
                    throw new IllegalArgumentException(rule.id() + ": threshold.minimum is required for distinct/sum");
                }
            }
            case SEQUENCE -> {
                SequenceSpec s = rule.sequence();
                if (s == null || s.steps().size() < 2 || s.windowSeconds() < 1 || s.windowSeconds() > 86_400) {
                    throw new IllegalArgumentException(rule.id() + ": sequence needs >= 2 steps and windowSeconds 1..86400");
                }
                for (SequenceSpec.Step step : s.steps()) {
                    if (step.condition() == null) {
                        throw new IllegalArgumentException(rule.id() + ": every sequence step needs a condition");
                    }
                }
            }
            case SINGLE -> {
            }
        }
    }

    public List<DetectionRule> all() {
        return List.copyOf(rules);
    }

    public List<DetectionRule> enabled() {
        return rules.stream().filter(DetectionRule::enabled).toList();
    }

    public Optional<DetectionRule> byId(String id) {
        return rules.stream().filter(rule -> rule.id().equals(id)).findFirst();
    }

    public List<RuleChange> history(String id) {
        return List.copyOf(history.getOrDefault(id, List.of()));
    }

    /**
     * Applies a change once. A change already applied (same changeId), e.g. this instance consuming the
     * record it just published, returns the current rule without bumping the version again.
     */
    public synchronized Optional<DetectionRule> apply(RuleChange change) {
        if (appliedChangeIds.contains(change.changeId())) {
            return byId(change.ruleId());
        }
        for (int i = 0; i < rules.size(); i++) {
            DetectionRule rule = rules.get(i);
            if (!rule.id().equals(change.ruleId())) {
                continue;
            }
            DetectionRule updated = switch (change.action()) {
                case ENABLE -> rule.withEnabled(true);
                case DISABLE -> rule.withEnabled(false);
                case SET_SEVERITY -> {
                    if (change.severity() == null) {
                        throw new IllegalArgumentException("severity is required for SET_SEVERITY");
                    }
                    yield rule.withSeverity(change.severity());
                }
            };
            rules.set(i, updated);
            appliedChangeIds.add(change.changeId());
            List<RuleChange> entries = history.computeIfAbsent(rule.id(), ignored -> new ArrayList<>());
            entries.add(change.withVersion(updated.version()));
            if (entries.size() > MAX_HISTORY_PER_RULE) {
                entries.removeFirst();
            }
            return Optional.of(updated);
        }
        return Optional.empty();
    }
}
