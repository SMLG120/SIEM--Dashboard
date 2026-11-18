package com.enterprise.siem.common.kafka;

import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.core.KafkaOperations;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.listener.CommonErrorHandler;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.ExponentialBackOff;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shared consumer error policy for every service that listens to Kafka.
 *
 * <ul>
 *   <li>Failed records are retried in place with exponential backoff (1s, 2s, 4s, 8s; about 15s total),
 *   so a short database or broker blip doesn't lose data.</li>
 *   <li>After the retries, the record is published to {@code <topic>.DLT} together with the
 *   exception headers Spring adds ({@code kafka_dlt-exception-message} etc.). Only then is the
 *   offset committed, so a failing record is never silently skipped.</li>
 *   <li>Records that can never succeed (deserialization failures, invalid payloads) go to the DLT
 *   immediately without retries.</li>
 * </ul>
 *
 * Services opt in simply by having spring-kafka on the classpath. Boot's listener container
 * factory picks up the {@link CommonErrorHandler} bean.
 */
@AutoConfiguration(afterName = "org.springframework.boot.kafka.autoconfigure.KafkaAutoConfiguration")
@ConditionalOnClass(KafkaTemplate.class)
public class SiemKafkaErrorHandlingAutoConfiguration {
    public static final String DLT_SUFFIX = ".DLT";
    private static final Logger log = LoggerFactory.getLogger(SiemKafkaErrorHandlingAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean(CommonErrorHandler.class)
    @ConditionalOnBean(ProducerFactory.class)
    DefaultErrorHandler siemKafkaErrorHandler(
            ProducerFactory<Object, Object> producerFactory,
            KafkaTemplate<Object, Object> kafkaTemplate,
            @Value("${siem.kafka.retry.initial-interval-ms:1000}") long initialInterval,
            @Value("${siem.kafka.retry.max-elapsed-ms:15000}") long maxElapsed) {

        // Deserialization failures arrive as raw bytes and must be republished as bytes, not JSON.
        KafkaTemplate<Object, Object> bytesTemplate = new KafkaTemplate<>(producerFactory,
                Map.of(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, ByteArraySerializer.class));
        Map<Class<?>, KafkaOperations<?, ?>> templates = new LinkedHashMap<>();
        templates.put(byte[].class, bytesTemplate);
        templates.put(Object.class, kafkaTemplate);

        DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(templates,
                // Partition -1 lets the producer choose, so DLT partition counts needn't match the source topic.
                (record, ex) -> new TopicPartition(record.topic() + DLT_SUFFIX, -1));

        ExponentialBackOff backOff = new ExponentialBackOff(initialInterval, 2.0);
        backOff.setMaxInterval(8_000);
        backOff.setMaxElapsedTime(maxElapsed);

        DefaultErrorHandler handler = new DefaultErrorHandler((record, ex) -> {
            log.error("Sending record {}-{}@{} to {}{} after failure: {}", record.topic(), record.partition(),
                    record.offset(), record.topic(), DLT_SUFFIX, ex.getMessage());
            recoverer.accept(record, ex);
        }, backOff);
        handler.addNotRetryableExceptions(IllegalArgumentException.class, NonRetryableRecordException.class);
        handler.setCommitRecovered(true);
        return handler;
    }
}
