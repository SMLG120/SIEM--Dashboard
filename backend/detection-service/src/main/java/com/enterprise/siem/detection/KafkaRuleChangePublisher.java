package com.enterprise.siem.detection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
public class KafkaRuleChangePublisher implements RuleChangePublisher {
    private static final Logger log = LoggerFactory.getLogger(KafkaRuleChangePublisher.class);

    private final KafkaTemplate<String, RuleChange> kafkaTemplate;

    public KafkaRuleChangePublisher(KafkaTemplate<String, RuleChange> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @Override
    public void publish(RuleChange change) {
        kafkaTemplate.send(RuleChangeConsumer.RULES_TOPIC, change.ruleId(), change);
        log.info("Published rule change {} for rule {}", change.action(), change.ruleId());
    }
}