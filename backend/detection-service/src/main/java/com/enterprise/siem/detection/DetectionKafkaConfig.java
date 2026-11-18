package com.enterprise.siem.detection;

import com.enterprise.siem.common.kafka.SiemKafkaErrorHandlingAutoConfiguration;
import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class DetectionKafkaConfig {
    @Bean
    DetectionEngine detectionEngine() {
        return new DetectionEngine();
    }

    @Bean
    NewTopic alertsTopic() {
        return TopicBuilder.name(EventConsumer.ALERTS_TOPIC)
                .partitions(3)
                .replicas(1)
                .build();
    }

    @Bean
    NewTopic eventsDeadLetterTopic() {
        // Failed or malformed events land here after retries; retained 14 days for inspection/replay.
        return TopicBuilder.name(EventConsumer.EVENTS_TOPIC + SiemKafkaErrorHandlingAutoConfiguration.DLT_SUFFIX)
                .partitions(1)
                .replicas(1)
                .config("retention.ms", String.valueOf(14L * 24 * 3600 * 1000))
                .build();
    }

    @Bean
    NewTopic rulesTopic() {
        // Rule changes are replayed on startup, so they must never expire.
        return TopicBuilder.name(RuleChangeConsumer.RULES_TOPIC)
                .partitions(RuleChangeConsumer.RULES_PARTITIONS)
                .replicas(1)
                .config("retention.ms", "-1")
                .build();
    }
}
