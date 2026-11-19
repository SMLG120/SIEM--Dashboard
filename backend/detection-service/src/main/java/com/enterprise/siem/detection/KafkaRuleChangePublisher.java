package com.enterprise.siem.detection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Component
public class KafkaRuleChangePublisher implements RuleChangePublisher {
    private static final Logger log = LoggerFactory.getLogger(KafkaRuleChangePublisher.class);

    private final KafkaTemplate<String, RuleChange> kafkaTemplate;

    public KafkaRuleChangePublisher(KafkaTemplate<String, RuleChange> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @Override
    public void publish(RuleChange change) {
        try {
            // Keyed by rule ID so changes to one rule stay ordered on one partition.
            kafkaTemplate.send(RuleChangeConsumer.RULES_TOPIC, change.ruleId(), change).get(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while publishing rule change", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Rule change could not be published; nothing was changed", e);
        }
        log.info("Published rule change {} for rule {}", change.action(), change.ruleId());
    }
}