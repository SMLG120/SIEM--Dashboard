package com.enterprise.siem.detection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.kafka.autoconfigure.ConcurrentKafkaListenerContainerFactoryConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.annotation.PartitionOffset;
import org.springframework.kafka.annotation.TopicPartition;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.stereotype.Component;

/**
 * Every detection instance must see every rule change, and rule state lives only in memory, so each
 * instance reads {@code siem.rules} from offset 0 on startup.
 *
 * <p>This uses manual partition assignment and never commits offsets. The previous design joined a
 * new random consumer group per start, which left an orphaned group on the broker after each restart.
 */
@Component
public class RuleChangeConsumer {
    public static final String RULES_TOPIC = "siem.rules";
    public static final int RULES_PARTITIONS = 3;

    private static final Logger log = LoggerFactory.getLogger(RuleChangeConsumer.class);

    private final RuleChangeService ruleChangeService;

    public RuleChangeConsumer(RuleChangeService ruleChangeService) {
        this.ruleChangeService = ruleChangeService;
    }

    @KafkaListener(id = "rule-change-replay",
            groupId = "detection-rules-replay",
            containerFactory = "ruleReplayContainerFactory",
            topicPartitions = @TopicPartition(topic = RULES_TOPIC,
                    // Explicit partitions (declared in DetectionKafkaConfig) so startup doesn't need a broker
                    // round-trip; keep in sync with RULES_PARTITIONS.
                    partitionOffsets = {
                            @PartitionOffset(partition = "0", initialOffset = "0"),
                            @PartitionOffset(partition = "1", initialOffset = "0"),
                            @PartitionOffset(partition = "2", initialOffset = "0")}),
            properties = "enable.auto.commit=false")
    public void onRuleChange(RuleChange change) {
        ruleChangeService.apply(change).ifPresentOrElse(
                updated -> log.info("Applied rule change {} -> rule {} v{} enabled={} severity={} (by {})",
                        change.action(), updated.id(), updated.version(), updated.enabled(), updated.severity(),
                        change.actor()),
                () -> log.warn("Ignored rule change for unknown rule {}", change.ruleId())
        );
    }

    @Configuration
    static class ReplayContainerConfig {
        @Bean
        ConcurrentKafkaListenerContainerFactory<Object, Object> ruleReplayContainerFactory(
                ConcurrentKafkaListenerContainerFactoryConfigurer configurer,
                ConsumerFactory<Object, Object> consumerFactory) {
            ConcurrentKafkaListenerContainerFactory<Object, Object> factory = new ConcurrentKafkaListenerContainerFactory<>();
            configurer.configure(factory, consumerFactory);
            // MANUAL without ever acknowledging: offsets are never committed, so no group state persists.
            factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL);
            return factory;
        }
    }
}
