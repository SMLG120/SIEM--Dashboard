package com.enterprise.siem.detection;

import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class RuleChangeService {
    private final DetectionRuleRepository ruleRepository;
    private final RuleChangePublisher publisher;

    public RuleChangeService(DetectionRuleRepository ruleRepository, RuleChangePublisher publisher) {
        this.ruleRepository = ruleRepository;
        this.publisher = publisher;
    }

    public Optional<DetectionRule> applyAndPublish(RuleChange change) {
        Optional<DetectionRule> updated = ruleRepository.apply(change);
        updated.ifPresent(rule -> publisher.publish(change));
        return updated;
    }

    public Optional<DetectionRule> apply(RuleChange change) {
        return ruleRepository.apply(change);
    }
}