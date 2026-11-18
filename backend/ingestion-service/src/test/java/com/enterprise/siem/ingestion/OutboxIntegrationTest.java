package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * End-to-end ingestion against real PostgreSQL (Testcontainers JDBC URL) and a real Kafka broker:
 * accepted events reach {@code siem.events}, retries are idempotent, and a batch is all-or-nothing.
 */
@Testcontainers
@SpringBootTest(properties = {
        "spring.kafka.admin.auto-create=true",
        "siem.outbox.poll-interval=100ms",
        "siem.outbox.relay-enabled=true"
})
class OutboxIntegrationTest {

    @Container
    @ServiceConnection
    static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:3.7.0");

    @Autowired
    EventIngestService service;
    @Autowired
    JdbcClient jdbc;

    private KafkaConsumer<String, String> consumer;

    @BeforeEach
    void subscribe() {
        consumer = new KafkaConsumer<>(Map.of(
                ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, KAFKA.getBootstrapServers(),
                ConsumerConfig.GROUP_ID_CONFIG, "test-" + UUID.randomUUID(),
                ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest",
                ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class,
                ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class));
        consumer.subscribe(List.of(EventIngestService.EVENTS_TOPIC));
    }

    @AfterEach
    void close() {
        consumer.close();
    }

    @Test
    void acceptedEventIsPublishedToKafkaAndOutboxIsDrained() {
        SecurityEvent event = service.ingest(request("LOGIN_FAILURE", "outbox-1"), "client-a");

        List<ConsumerRecord<String, String>> records = pollFor(event.id(), Duration.ofSeconds(30));
        assertThat(records).extracting(ConsumerRecord::key).contains(event.id());
        assertThat(records.getFirst().value()).contains("\"eventType\":\"LOGIN_FAILURE\"").contains("\"schemaVersion\":2");

        awaitOutboxDrained(event.id());
    }

    @Test
    void retryWithSameSourceEventIdIsStoredAndPublishedOnce() {
        SecurityEvent first = service.ingest(request("PORT_SCAN", "retry-42"), "client-a");
        SecurityEvent retry = service.ingest(request("PORT_SCAN", "retry-42"), "client-a");
        SecurityEvent otherClient = service.ingest(request("PORT_SCAN", "retry-42"), "client-b");

        assertThat(retry.id()).isEqualTo(first.id());
        assertThat(otherClient.id()).isNotEqualTo(first.id());
        assertThat(count("SELECT COUNT(*) FROM siem_event WHERE id = :id", first.id())).isEqualTo(1);
        assertThat(count("SELECT COUNT(*) FROM siem_event_outbox WHERE event_id = :id", first.id())).isEqualTo(1);
    }

    @Test
    void invalidEventRollsBackTheWholeBatch() {
        long before = count("SELECT COUNT(*) FROM siem_event", null);
        IngestEventRequest good = request("MALWARE_DETECTED", null);
        IngestEventRequest future = new IngestEventRequest("MALWARE_DETECTED", EventSeverity.HIGH, null, "10.0.0.9",
                null, null, null, null, null, null, Instant.now().plus(Duration.ofDays(1)));

        assertThatThrownBy(() -> service.ingestBatch(List.of(good, future), "client-a"))
                .isInstanceOf(ResponseStatusException.class);
        assertThat(count("SELECT COUNT(*) FROM siem_event", null)).isEqualTo(before);
    }

    @Test
    void eventStaysPendingWhileKafkaIsUnavailableThenPublishes() {
        KAFKA.getDockerClient().pauseContainerCmd(KAFKA.getContainerId()).exec();
        String id;
        try {
            id = service.ingest(request("C2_BEACON", null), "client-a").id();
            sleep(Duration.ofSeconds(3));
            assertThat(count("SELECT COUNT(*) FROM siem_event_outbox WHERE event_id = :id AND published_at IS NULL", id))
                    .as("event remains queued, not lost, while the broker is down")
                    .isEqualTo(1);
        } finally {
            KAFKA.getDockerClient().unpauseContainerCmd(KAFKA.getContainerId()).exec();
        }
        assertThat(pollFor(id, Duration.ofSeconds(60))).extracting(ConsumerRecord::key).contains(id);
        awaitOutboxDrained(id);
    }

    private List<ConsumerRecord<String, String>> pollFor(String key, Duration timeout) {
        List<ConsumerRecord<String, String>> matched = new ArrayList<>();
        Instant deadline = Instant.now().plus(timeout);
        while (matched.isEmpty() && Instant.now().isBefore(deadline)) {
            consumer.poll(Duration.ofMillis(500)).forEach(r -> {
                if (key.equals(r.key())) {
                    matched.add(r);
                }
            });
        }
        return matched;
    }

    private void awaitOutboxDrained(String eventId) {
        Instant deadline = Instant.now().plusSeconds(20);
        while (Instant.now().isBefore(deadline)) {
            if (count("SELECT COUNT(*) FROM siem_event_outbox WHERE event_id = :id AND published_at IS NULL", eventId) == 0) {
                return;
            }
            sleep(Duration.ofMillis(200));
        }
        throw new AssertionError("outbox row for " + eventId + " was never marked published");
    }

    private long count(String sql, String id) {
        var spec = jdbc.sql(sql);
        if (id != null) {
            spec = spec.param("id", id);
        }
        return spec.query(Long.class).single();
    }

    private static IngestEventRequest request(String type, String sourceEventId) {
        return new IngestEventRequest(type, EventSeverity.HIGH, "TEST", "10.0.0.5", "host-1", "10.0.0.1", 443,
                "alice", "synthetic test event", sourceEventId, null);
    }

    private static void sleep(Duration d) {
        try {
            Thread.sleep(d.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
