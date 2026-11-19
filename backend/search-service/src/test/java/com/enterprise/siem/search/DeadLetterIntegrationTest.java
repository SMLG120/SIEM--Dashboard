package com.enterprise.siem.search;

import com.enterprise.siem.common.kafka.NonRetryableRecordException;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.kafka.support.serializer.JacksonJsonSerializer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A record that can never be processed must land on {@code siem.events.DLT} as readable JSON and must
 * not block the partition. Regression: a consumer-only service's error handler used the String
 * producer to dead-letter typed payloads, the publish failed, and the record was retried forever.
 */
@Testcontainers
@SpringBootTest(properties = {
        "spring.kafka.listener.auto-startup=true",
        "spring.kafka.admin.auto-create=true",
        "siem.kafka.retry.max-elapsed-ms=500"
})
class DeadLetterIntegrationTest {

    @Container
    @ServiceConnection
    static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:3.7.0");

    static final Set<String> INDEXED = ConcurrentHashMap.newKeySet();

    @TestConfiguration
    static class FailingIndex {
        @Bean
        @Primary
        SearchIndex failingForPoison() {
            return new InMemorySearchIndex() {
                @Override
                public void index(String indexName, String id, Map<String, Object> document) {
                    if (id.startsWith("poison")) {
                        throw new NonRetryableRecordException("cannot index " + id);
                    }
                    super.index(indexName, id, document);
                    INDEXED.add(id);
                }
            };
        }
    }

    @Test
    void poisonRecordIsDeadLetteredAsJsonAndLaterRecordsStillFlow() throws Exception {
        String poison = "poison-" + UUID.randomUUID();
        String healthy = "ok-" + UUID.randomUUID();
        try (KafkaProducer<String, SecurityEvent> producer = new KafkaProducer<>(Map.of(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers()),
                new StringSerializer(), new JacksonJsonSerializer<>())) {
            // Same partition, poison first: the healthy record is only reachable if the poison one is recovered.
            producer.send(new ProducerRecord<>("siem.events", 0, poison, event(poison))).get();
            producer.send(new ProducerRecord<>("siem.events", 0, healthy, event(healthy))).get();
        }

        List<ConsumerRecord<String, String>> dlt = new ArrayList<>();
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers(),
                ConsumerConfig.GROUP_ID_CONFIG, "dlt-reader-" + UUID.randomUUID(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest"), new StringDeserializer(), new StringDeserializer())) {
            consumer.subscribe(List.of("siem.events.DLT"));
            long deadline = System.currentTimeMillis() + 60_000;
            while (dlt.isEmpty() && System.currentTimeMillis() < deadline) {
                consumer.poll(Duration.ofMillis(500)).forEach(dlt::add);
            }
        }

        assertThat(dlt).hasSize(1);
        assertThat(dlt.getFirst().key()).isEqualTo(poison);
        assertThat(dlt.getFirst().value()).contains("\"id\":\"" + poison + "\"").contains("\"eventType\":\"MALWARE_DETECTED\"");
        assertThat(new String(dlt.getFirst().headers().lastHeader("kafka_dlt-exception-message").value()))
                .contains("cannot index");

        long deadline = System.currentTimeMillis() + 30_000;
        while (!INDEXED.contains(healthy) && System.currentTimeMillis() < deadline) {
            Thread.sleep(200);
        }
        assertThat(INDEXED).as("partition is not blocked by the poison record").contains(healthy);
    }

    private static SecurityEvent event(String id) {
        return new SecurityEvent(id, Instant.parse("2026-11-18T12:00:00Z"), "MALWARE_DETECTED", EventSeverity.HIGH,
                null, "10.0.0.5", null, null, null, null, null);
    }
}
