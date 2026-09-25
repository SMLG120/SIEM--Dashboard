package com.enterprise.siem.detection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
public class RuleChangeConsumer {
    public static final String RULES_TOPIC = "siem.rules";

    private static final Logger log = LoggerFactory.getLogger(RuleChangeConsumer.class);

    private final RuleChangeService ruleChangeService;

    public RuleChangeConsumer(RuleChangeService ruleChangeService) {
        this.ruleChangeService = ruleChangeService;
    }

    @KafkaListener(topics = RULES_TOPIC, groupId = "detection-rules")
    public void onRuleChange(RuleChange change) {
        ruleChangeService.apply(change).ifPresentOrElse(
                updated -> log.info("Applied rule change {} -> rule {} is now enabled={}",
                        change.action(), updated.id(), updated.enabled()),
                () -> log.warn("Ignored rule change for unknown rule {}", change.ruleId())
        );
    }
}