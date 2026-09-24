package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.SiemAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Component
public class AlertConsumer {
    private static final Logger log = LoggerFactory.getLogger(AlertConsumer.class);

    private final AlertStore alertStore;

    public AlertConsumer(AlertStore alertStore) {
        this.alertStore = alertStore;
    }

    @KafkaListener(topics = "siem.alerts", groupId = "alert-service")
    public void onAlert(SiemAlert alert) {
        alertStore.add(alert);
        log.info("Stored alert {} from rule {}", alert.id(), alert.ruleId());
    }
}