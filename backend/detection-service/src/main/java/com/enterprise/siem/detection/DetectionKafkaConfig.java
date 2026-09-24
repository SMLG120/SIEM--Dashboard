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
}