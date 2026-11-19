package com.enterprise.siem.detection;

import com.enterprise.siem.common.kafka.NonRetryableRecordException;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Evaluates every enabled rule against each event and publishes the resulting alerts.
 *
 * <p>Delivery: the listener waits for the broker to acknowledge each alert. If a send fails, the
 * exception propagates, the offset is <em>not</em> committed, and the shared error handler retries
 * the record and then dead-letters it to {@code siem.events.DLT}. Alerts are therefore delivered at
 * least once, and their deterministic IDs make re-delivery harmless downstream.
 */
@Component
public class EventConsumer {
    private static final Logger log = LoggerFactory.getLogger(EventConsumer.class);
    public static final String EVENTS_TOPIC = "siem.events";
    public static final String ALERTS_TOPIC = "siem.alerts";

    private final DetectionRuleRepository ruleRepository;
    private final DetectionEngine engine;
    private final DetectionMetrics metrics;
    private final RecentAlertStore recentAlerts;
    private final KafkaTemplate<String, SiemAlert> kafkaTemplate;
    private final Duration sendTimeout;

    public EventConsumer(
            DetectionRuleRepository ruleRepository,
            DetectionEngine engine,
            DetectionMetrics metrics,
            RecentAlertStore recentAlerts,
            KafkaTemplate<String, SiemAlert> kafkaTemplate,
            @Value("${siem.detection.send-timeout:10s}") Duration sendTimeout
    ) {
        this.ruleRepository = ruleRepository;
        this.engine = engine;
        this.metrics = metrics;
        this.recentAlerts = recentAlerts;
        this.kafkaTemplate = kafkaTemplate;
        this.sendTimeout = sendTimeout;
    }

    @KafkaListener(topics = EVENTS_TOPIC, groupId = "detection-service")
    public void onEvent(SecurityEvent event) {
        if (event == null || event.id() == null || event.eventType() == null || event.severity() == null) {
            throw new NonRetryableRecordException("event is missing id, eventType or severity");
        }
        metrics.incrementEvaluated();
        for (DetectionRule rule : ruleRepository.enabled()) {
            List<SiemAlert> alerts = engine.evaluate(event, rule);
            for (SiemAlert alert : alerts) {
                publish(alert);
                recentAlerts.add(alert);
                metrics.alertGenerated(alert, event);
                log.info("Rule {} v{} matched event {} -> alert {}", rule.id(), rule.version(), event.id(), alert.id());
            }
        }
    }

    private void publish(SiemAlert alert) {
        try {
            kafkaTemplate.send(ALERTS_TOPIC, alert.id(), alert).get(sendTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while publishing alert " + alert.id(), e);
        } catch (ExecutionException | TimeoutException e) {
            throw new IllegalStateException("Failed to publish alert " + alert.id() + ": " + e.getMessage(), e);
        }
    }
}
