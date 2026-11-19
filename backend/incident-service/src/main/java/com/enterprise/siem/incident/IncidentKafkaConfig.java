package com.enterprise.siem.incident;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaTemplate;

import java.time.Instant;

@Configuration
public class IncidentKafkaConfig {
    public static final String INCIDENTS_TOPIC = "siem.incidents";

    private final KafkaTemplate<String, IncidentEvent> kafkaTemplate;

    public IncidentKafkaConfig(KafkaTemplate<String, IncidentEvent> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    @Bean
    NewTopic incidentsTopic() {
        return TopicBuilder.name(INCIDENTS_TOPIC)
                .partitions(3)
                .replicas(1)
                .build();
    }

    public void publish(String incidentId, String title, String action) {
        publish(new IncidentEvent(incidentId, title, action, Instant.now()));
    }

    /** Best effort: the incident row and its timeline are the record; this is a notification. */
    public void publish(IncidentEvent event) {
        try {
            kafkaTemplate.send(INCIDENTS_TOPIC, event.incidentId(), event);
        } catch (Exception e) {
            log.warn("Failed to publish incident event to {}: {}", INCIDENTS_TOPIC, e.getMessage());
        }
    }

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(IncidentKafkaConfig.class);
}