package com.enterprise.siem.alert;

import com.enterprise.siem.common.kafka.NonRetryableRecordException;
import com.enterprise.siem.common.model.SiemAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Persists alerts from {@code siem.alerts}. The offset is committed only after the transaction
 * commits; a failure is retried and then dead-lettered to {@code siem.alerts.DLT}.
 */
@Component
public class AlertConsumer {
    private static final Logger log = LoggerFactory.getLogger(AlertConsumer.class);

    private final AlertService alertService;

    public AlertConsumer(AlertService alertService) {
        this.alertService = alertService;
    }

    @KafkaListener(topics = "siem.alerts", groupId = "alert-service")
    public void onAlert(SiemAlert alert) {
        if (alert == null || alert.id() == null || alert.ruleId() == null || alert.severity() == null
                || alert.createdAt() == null) {
            throw new NonRetryableRecordException("alert is missing id, ruleId, severity or createdAt");
        }
        if (alertService.record(alert)) {
            log.info("Stored alert {} from rule {}", alert.id(), alert.ruleId());
        } else {
            log.debug("Alert {} already stored (redelivery)", alert.id());
        }
    }
}
