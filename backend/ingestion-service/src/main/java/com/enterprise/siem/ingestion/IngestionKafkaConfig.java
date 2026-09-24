package com.enterprise.siem.ingestion;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class IngestionKafkaConfig {
    @Bean
    NewTopic eventsTopic() {
        return TopicBuilder.name(EventIngestService.EVENTS_TOPIC)
                .partitions(3)
                .replicas(1)
                .build();
    }
}