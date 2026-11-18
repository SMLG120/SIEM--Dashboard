package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentStatus;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.kafka.support.serializer.JacksonJsonSerializer;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Runs against PostgreSQL (Testcontainers) because correlation relies on row and advisory locks. */
@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({IncidentRepository.class, IncidentService.class, JacksonAutoConfiguration.class,
        IncidentServiceTest.NoopKafka.class})
class IncidentServiceTest {

    @Autowired
    private IncidentService service;

    @Autowired
    private IncidentRepository repository;

    @Test
    void aggregatesCorrelatedAlertsIntoOneIncident() {
        service.correlate(alert("a1", "10.0.0.5", EventSeverity.CRITICAL));
        service.correlate(alert("a2", "10.0.0.5", EventSeverity.HIGH));
        service.correlate(alert("a3", "10.0.0.9", EventSeverity.CRITICAL));

        List<Incident> incidents = repository.recent(10);
        assertEquals(2, incidents.size());
        Incident ipIncident = incidents.stream()
                .filter(i -> i.relatedAlerts().stream().anyMatch(a -> "10.0.0.5".equals(a.sourceIp())))
                .findFirst().orElseThrow();
        assertEquals(2, ipIncident.relatedAlerts().size());
        assertEquals(EventSeverity.CRITICAL, ipIncident.severity());
    }

    @Test
    void doesNotDuplicateAlertLinks() {
        SiemAlert alert = alert("a1", "10.0.0.5", EventSeverity.HIGH);
        service.correlate(alert);
        service.correlate(alert);

        Incident incident = repository.recent(10).getFirst();
        assertEquals(1, incident.relatedAlerts().size());
        assertEquals(1, incident.timeline().size());
    }

    @Test
    void differentSourcesRemainSeparateIncidents() {
        service.correlate(alert("a1", "10.0.0.1", EventSeverity.LOW));
        service.correlate(alert("a2", "10.0.0.2", EventSeverity.LOW));
        assertEquals(2, repository.recent(10).size());
    }

    @Test
    void higherSeverityAlertEscalatesTheIncident() {
        service.correlate(alert("a1", "10.0.0.7", EventSeverity.LOW));
        Incident escalated = service.correlate(alert("a2", "10.0.0.7", EventSeverity.CRITICAL)).orElseThrow();
        assertEquals(EventSeverity.CRITICAL, escalated.severity());
        assertThat(escalated.timeline()).anyMatch(t -> t.action().equals("SEVERITY_CHANGED"));
    }

    @Test
    void closedIncidentsAreNotReusedAndClosingIsFinalExceptReopen() {
        Incident first = service.correlate(alert("a1", "10.0.0.8", EventSeverity.MEDIUM)).orElseThrow();
        service.updateStatus(first.id(), IncidentStatus.CLOSED, "manager");
        assertThrows(IncidentWorkflow.InvalidTransitionException.class,
                () -> service.updateStatus(first.id(), IncidentStatus.CONTAINED, "analyst"));

        Incident second = service.correlate(alert("a2", "10.0.0.8", EventSeverity.MEDIUM)).orElseThrow();
        assertThat(second.id()).isNotEqualTo(first.id());
        assertEquals(IncidentStatus.OPEN, service.updateStatus(first.id(), IncidentStatus.OPEN, "manager").status());
    }

    @TestConfiguration
    static class NoopKafka {
        @Bean
        IncidentKafkaConfig incidentKafkaConfig() {
            DefaultKafkaProducerFactory<String, IncidentEvent> factory = new DefaultKafkaProducerFactory<>(Map.of(
                    ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:1",
                    ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName(),
                    ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JacksonJsonSerializer.class.getName()));
            return new IncidentKafkaConfig(new KafkaTemplate<>(factory) {
                @Override
                public CompletableFuture<SendResult<String, IncidentEvent>> send(String topic, String key, IncidentEvent value) {
                    return CompletableFuture.completedFuture(null);
                }
            });
        }
    }

    private static SiemAlert alert(String id, String sourceIp, EventSeverity severity) {
        return new SiemAlert(id, Instant.now(), "SIEM-1001", "Test Rule", "Generates an alert", severity,
                "LOGIN_FAILURE", "EVT-" + id, sourceIp, "analyst", AlertStatus.OPEN);
    }
}
