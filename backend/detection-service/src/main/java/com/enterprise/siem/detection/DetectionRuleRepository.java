package com.enterprise.siem.detection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

@Repository
public class DetectionRuleRepository {
    private final List<DetectionRule> rules = new CopyOnWriteArrayList<>();

    public DetectionRuleRepository(ObjectMapper objectMapper) {
        try (InputStream in = getClass().getResourceAsStream("/detection-rules.json")) {
            List<DetectionRule> loaded = objectMapper.readValue(in, new TypeReference<>() {
            });
            this.rules.addAll(loaded);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load detection rules", e);
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

    public Optional<DetectionRule> apply(RuleChange change) {
        for (int i = 0; i < rules.size(); i++) {
            DetectionRule rule = rules.get(i);
            if (!rule.id().equals(change.ruleId())) {
                continue;
            }
            DetectionRule updated = switch (change.action()) {
                case ENABLE -> withFlag(rule, true);
                case DISABLE -> withFlag(rule, false);
                case SET_SEVERITY -> {
                    if (change.severity() == null) {
                        throw new IllegalArgumentException("severity is required for SET_SEVERITY");
                    }
                    yield new DetectionRule(
                            rule.id(),
                            rule.name(),
                            rule.description(),
                            change.severity(),
                            rule.enabled(),
                            rule.condition()
                    );
                }
            };
            rules.set(i, updated);
            return Optional.of(updated);
        }
        return Optional.empty();
    }

    private DetectionRule withFlag(DetectionRule rule, boolean enabled) {
        return new DetectionRule(
                rule.id(),
                rule.name(),
                rule.description(),
                rule.severity(),
                enabled,
                rule.condition()
        );
    }
}