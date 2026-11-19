package com.enterprise.siem.audit;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
class AuditKafkaConfig {
    /** Alert workflow history forwarded by the alert service; retained 30 days. */
    @Bean
    NewTopic auditTopic() {
        return TopicBuilder.name("siem.audit").partitions(3).replicas(1)
                .config("retention.ms", String.valueOf(30L * 24 * 3600 * 1000)).build();
    }
}
