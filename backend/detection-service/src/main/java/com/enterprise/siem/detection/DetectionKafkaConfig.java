package com.enterprise.siem.detection;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class DetectionKafkaConfig {
    @Bean
    NewTopic alertsTopic() {
        return TopicBuilder.name(EventConsumer.ALERTS_TOPIC)
                .partitions(3)
                .replicas(1)
                .build();
    }

    @Bean
    NewTopic rulesTopic() {
        // Rule changes are replayed on startup, so they must never expire.
        return TopicBuilder.name(RuleChangeConsumer.RULES_TOPIC)
                .partitions(3)
                .replicas(1)
                .config("retention.ms", "-1")
                .build();
    }
}