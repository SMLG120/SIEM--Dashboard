package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.SecurityEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Publishes outbox rows to Kafka in insertion order and marks each one only after the broker
 * acknowledges it ({@code acks=all}). On the first failure the batch stops, so a broker outage
 * simply leaves rows pending until the next tick; nothing is skipped or reordered.
 */
@Component
@ConditionalOnProperty(name = "siem.outbox.relay-enabled", havingValue = "true", matchIfMissing = true)
public class OutboxRelay {
    private static final Logger log = LoggerFactory.getLogger(OutboxRelay.class);

    private final OutboxRepository outbox;
    private final KafkaTemplate<String, SecurityEvent> kafkaTemplate;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactions;
    private final int batchSize;
    private final Duration sendTimeout;
    private final Counter published;
    private final Counter failures;
    private final AtomicLong pending = new AtomicLong();
    private final AtomicLong oldestPendingSeconds = new AtomicLong();

    public OutboxRelay(OutboxRepository outbox,
                       KafkaTemplate<String, SecurityEvent> kafkaTemplate,
                       ObjectMapper objectMapper,
                       TransactionTemplate transactions,
                       MeterRegistry meterRegistry,
                       @Value("${siem.outbox.batch-size:200}") int batchSize,
                       @Value("${siem.outbox.send-timeout:10s}") Duration sendTimeout) {
        this.outbox = outbox;
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
        this.transactions = transactions;
        this.batchSize = batchSize;
        this.sendTimeout = sendTimeout;
        this.published = meterRegistry.counter("siem_outbox_published_total");
        this.failures = meterRegistry.counter("siem_outbox_publish_failures_total");
        Gauge.builder("siem_outbox_pending", pending, AtomicLong::get)
                .description("Events accepted but not yet acknowledged by Kafka")
                .register(meterRegistry);
        Gauge.builder("siem_outbox_oldest_pending_seconds", oldestPendingSeconds, AtomicLong::get)
                .description("Age of the oldest unpublished event")
                .register(meterRegistry);
    }

    @Scheduled(fixedDelayString = "${siem.outbox.poll-interval:250ms}")
    public void relay() {
        int sent;
        do {
            sent = relayBatch();
        } while (sent == batchSize); // drain a backlog quickly, then go back to polling
    }

    /** @return number of rows published in this batch. */
    int relayBatch() {
        Integer count = transactions.execute(status -> {
            List<OutboxRepository.OutboxMessage> batch = outbox.lockPending(batchSize);
            int ok = 0;
            for (OutboxRepository.OutboxMessage message : batch) {
                try {
                    SecurityEvent event = objectMapper.readValue(message.payload(), SecurityEvent.class);
                    kafkaTemplate.send(message.topic(), message.key(), event)
                            .get(sendTimeout.toMillis(), TimeUnit.MILLISECONDS);
                    outbox.markPublished(message.id(), Instant.now());
                    ok++;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    outbox.markFailed(message.id(), "interrupted");
                    break;
                } catch (ExecutionException | TimeoutException | RuntimeException e) {
                    failures.increment();
                    String reason = e instanceof ExecutionException && e.getCause() != null
                            ? e.getCause().toString() : e.toString();
                    outbox.markFailed(message.id(), reason);
                    log.warn("Outbox publish of event {} failed (attempt {}): {}", message.eventId(),
                            message.attempts() + 1, reason);
                    break; // preserve order: retry this row first on the next tick
                }
            }
            return ok;
        });
        int sent = count == null ? 0 : count;
        published.increment(sent);
        return sent;
    }

    @Scheduled(fixedDelayString = "${siem.outbox.metrics-interval:15s}")
    public void refreshMetrics() {
        try {
            pending.set(outbox.pendingCount());
            oldestPendingSeconds.set(outbox.oldestPendingAge(Instant.now()).toSeconds());
        } catch (RuntimeException e) {
            log.debug("Outbox metrics refresh failed: {}", e.getMessage());
        }
    }

    @Scheduled(cron = "${siem.outbox.cleanup-cron:0 17 3 * * *}")
    public void cleanup() {
        int deleted = outbox.deletePublishedBefore(Instant.now().minus(Duration.ofDays(7)));
        log.info("Deleted {} published outbox rows older than 7 days", deleted);
    }
}
