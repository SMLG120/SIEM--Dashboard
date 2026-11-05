package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.SiemAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
public class AlertCorrelationConsumer {
    private static final Logger log = LoggerFactory.getLogger(AlertCorrelationConsumer.class);

    private final IncidentService incidentService;

    public AlertCorrelationConsumer(IncidentService incidentService) {
        this.incidentService = incidentService;
    }

    @KafkaListener(topics = "siem.alerts", groupId = "incident-service")
    public void onAlert(SiemAlert alert) {
        try {
            incidentService.correlate(alert);
        } catch (RuntimeException e) {
            // Rethrow so the container's error handler retries and logs the record instead of dropping it.
            log.error("Correlation failed for alert {}: {}", alert.id(), e.getMessage());
            throw e;
        }
    }
}