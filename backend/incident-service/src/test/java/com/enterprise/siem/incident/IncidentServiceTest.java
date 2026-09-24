package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
import com.enterprise.siem.incident.model.Incident;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class IncidentServiceTest {

    @Test
    void aggregatesCorrelatedAlertsIntoOneIncident() {
        IncidentStore store = new IncidentStore();
        IncidentService service = new IncidentService(store, new IncidentKafkaConfig(noopTemplate()));

        service.correlate(alert("a1", "10.0.0.5", "SIEM-1001", EventSeverity.CRITICAL));
        service.correlate(alert("a2", "10.0.0.5", "SIEM-1002", EventSeverity.HIGH));
        service.correlate(alert("a3", "10.0.0.9", "SIEM-1001", EventSeverity.CRITICAL));

        assertEquals(2, store.all().size());

        Incident ipIncident = store.all().stream()
                .filter(incident -> incident.relatedAlerts().stream()
                        .anyMatch(alert -> "10.0.0.5".equals(alert.sourceIp())))
                .findFirst().orElseThrow();

        assertEquals(2, ipIncident.relatedAlerts().size());
        assertSame(EventSeverity.CRITICAL, ipIncident.severity());
    }

    @Test
    void doesNotDuplicateAlertLinks() {
        IncidentStore store = new IncidentStore();
        IncidentService service = new IncidentService(store, new IncidentKafkaConfig(noopTemplate()));

        SiemAlert alert = alert("a1", "10.0.0.5", "SIEM-1001", EventSeverity.HIGH);
        service.correlate(alert);
        service.correlate(alert);

        Incident incident = store.all().get(0);
        assertEquals(1, incident.relatedAlerts().size());
        assertEquals(0, incident.timeline().stream().filter(entry -> entry.action().equals("ALERT_LINKED")).count());
        assertEquals(1, incident.timeline().size());
    }

    @Test
    void differentSourcesRemainSeparateIncidents() {
        IncidentStore store = new IncidentStore();
        IncidentService service = new IncidentService(store, new IncidentKafkaConfig(noopTemplate()));

        service.correlate(alert("a1", "10.0.0.1", "SIEM-1001", EventSeverity.LOW));
        service.correlate(alert("a2", "10.0.0.2", "SIEM-1001", EventSeverity.LOW));

        assertEquals(2, store.all().size());
    }

    private KafkaTemplate<String, IncidentEvent> noopTemplate() {
        DefaultKafkaProducerFactory<String, IncidentEvent> factory =
                new DefaultKafkaProducerFactory<>(Map.of(
                        ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092",
                        ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName(),
                        ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class.getName()
                ));
        return new KafkaTemplate<>(factory) {
            @Override
            public CompletableFuture<SendResult<String, IncidentEvent>> send(String topic, String key, IncidentEvent value) {
                return CompletableFuture.completedFuture(null);
            }
        };
    }

    private SiemAlert alert(String id, String sourceIp, String ruleId, EventSeverity severity) {
        return new SiemAlert(
                id,
                Instant.now(),
                ruleId,
                "Test Rule",
                "Generates an alert",
                severity,
                "LOGIN_FAILURE",
                "EVT-" + id,
                sourceIp,
                "analyst",
                AlertStatus.OPEN
        );
    }
}