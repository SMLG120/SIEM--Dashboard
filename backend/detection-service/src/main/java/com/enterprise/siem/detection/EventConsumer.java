package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
public class EventConsumer {
    private static final Logger log = LoggerFactory.getLogger(EventConsumer.class);
    public static final String ALERTS_TOPIC = "siem.alerts";

    private final DetectionRuleRepository ruleRepository;
    private final DetectionEngine engine;
    private final DetectionMetrics metrics;
    private final RecentAlertStore recentAlerts;
    private final KafkaTemplate<String, SiemAlert> kafkaTemplate;

    public EventConsumer(
            DetectionRuleRepository ruleRepository,
            DetectionEngine engine,
            DetectionMetrics metrics,
            RecentAlertStore recentAlerts,
            KafkaTemplate<String, SiemAlert> kafkaTemplate
    ) {
        this.ruleRepository = ruleRepository;
        this.engine = engine;
        this.metrics = metrics;
        this.recentAlerts = recentAlerts;
        this.kafkaTemplate = kafkaTemplate;
    }

    @KafkaListener(topics = "siem.events", groupId = "detection-service")
    public void onEvent(SecurityEvent event) {
        metrics.incrementEvaluated();
        for (DetectionRule rule : ruleRepository.enabled()) {
            engine.evaluate(event, rule).ifPresent(alert -> {
                recentAlerts.add(alert);
                kafkaTemplate.send(ALERTS_TOPIC, alert.id(), alert);
                metrics.incrementGenerated();
                log.info("Rule {} matched event {} -> alert {}", rule.id(), event.id(), alert.id());
            });
        }
    }
}