package com.enterprise.siem.detection;

import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class RuleChangeService {
    private final DetectionRuleRepository ruleRepository;
    private final RuleChangePublisher publisher;
    private final DetectionEngine engine;

    public RuleChangeService(DetectionRuleRepository ruleRepository, RuleChangePublisher publisher) {
        this(ruleRepository, publisher, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public RuleChangeService(DetectionRuleRepository ruleRepository, RuleChangePublisher publisher,
                             DetectionEngine engine) {
        this.ruleRepository = ruleRepository;
        this.publisher = publisher;
        this.engine = engine;
    }

    /**
     * Publishes first (waiting for the broker's ack), then applies locally. If publishing fails nothing
     * changes, so this instance can't drift from the replay log that other instances and future
     * restarts rebuild from. When this instance later consumes its own record, the repository
     * recognises the changeId and skips it.
     */
    public Optional<DetectionRule> applyAndPublish(RuleChange change) {
        if (ruleRepository.byId(change.ruleId()).isEmpty()) {
            return Optional.empty();
        }
        if (change.action() == RuleChangeAction.SET_SEVERITY && change.severity() == null) {
            throw new IllegalArgumentException("severity is required for SET_SEVERITY");
        }
        publisher.publish(change);
        return apply(change);
    }

    public Optional<DetectionRule> apply(RuleChange change) {
        Optional<DetectionRule> updated = ruleRepository.apply(change);
        updated.filter(rule -> !rule.enabled()).ifPresent(rule -> {
            if (engine != null) {
                engine.reset(rule.id()); // stale correlation state must not fire when re-enabled
            }
        });
        return updated;
    }
}