package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.ids.DeterministicIds;
import com.enterprise.siem.common.model.SecurityEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import tools.jackson.databind.ObjectMapper;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Normalises, stores and queues events for publication.
 *
 * <p>Delivery guarantee: the event row and its outbox row commit in one database transaction, and
 * {@link OutboxRelay} publishes outbox rows to Kafka afterwards, marking them only once the broker
 * acknowledges. An accepted event ({@code 201}) is therefore published <em>at least once</em>, even if
 * Kafka is down at the time of the request. Duplicates are possible (a crash between the broker ack
 * and the mark); every consumer is idempotent on the event ID.
 */
@Service
public class EventIngestService {
    public static final String EVENTS_TOPIC = "siem.events";
    static final Duration MAX_FUTURE_SKEW = Duration.ofMinutes(5);
    static final Duration MAX_EVENT_AGE = Duration.ofDays(30);

    private final EventRepository eventRepository;
    private final OutboxRepository outbox;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final Counter accepted;
    private final Counter duplicates;

    @Autowired
    public EventIngestService(EventRepository eventRepository, OutboxRepository outbox, ObjectMapper objectMapper,
                              MeterRegistry meterRegistry) {
        this(eventRepository, outbox, objectMapper, meterRegistry, Clock.systemUTC());
    }

    EventIngestService(EventRepository eventRepository, OutboxRepository outbox, ObjectMapper objectMapper,
                       MeterRegistry meterRegistry, Clock clock) {
        this.eventRepository = eventRepository;
        this.outbox = outbox;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.accepted = meterRegistry.counter("siem_ingestion_events_accepted_total");
        this.duplicates = meterRegistry.counter("siem_ingestion_events_duplicate_total");
    }

    @Transactional
    public SecurityEvent ingest(IngestEventRequest request, String clientId) {
        return store(request, clientId);
    }

    /** All-or-nothing: a single invalid or failing event rolls the whole batch back. */
    @Transactional
    public List<SecurityEvent> ingestBatch(List<IngestEventRequest> requests, String clientId) {
        return requests.stream().map(request -> store(request, clientId)).toList();
    }

    private SecurityEvent store(IngestEventRequest request, String clientId) {
        Instant receivedAt = clock.instant();
        Instant eventTime = eventTime(request.occurredAt(), receivedAt);
        String id = request.sourceEventId() == null || request.sourceEventId().isBlank()
                ? UUID.randomUUID().toString()
                // Scoped by the authenticated client so one client can't collide with another's IDs.
                : DeterministicIds.of("siem-event", clientId, request.sourceEventId());

        SecurityEvent event = new SecurityEvent(
                id,
                eventTime,
                request.normalizedEventType(),
                request.severity(),
                request.effectiveCategory(),
                request.sourceIp(),
                request.sourceHost(),
                request.destinationIp(),
                request.destinationPort(),
                request.userName(),
                request.message(),
                SecurityEvent.CURRENT_SCHEMA_VERSION
        );

        if (!eventRepository.insert(event, receivedAt, request.sourceEventId())) {
            // A retry of an event we already accepted: return the stored copy, enqueue nothing.
            duplicates.increment();
            return eventRepository.findById(id).orElse(event);
        }
        outbox.append(id, EVENTS_TOPIC, id, objectMapper.writeValueAsString(event), receivedAt);
        accepted.increment();
        return event;
    }

    private Instant eventTime(Instant occurredAt, Instant receivedAt) {
        if (occurredAt == null) {
            return receivedAt;
        }
        if (occurredAt.isAfter(receivedAt.plus(MAX_FUTURE_SKEW))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "occurredAt is more than " + MAX_FUTURE_SKEW.toMinutes() + " minutes in the future");
        }
        if (occurredAt.isBefore(receivedAt.minus(MAX_EVENT_AGE))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "occurredAt is older than " + MAX_EVENT_AGE.toDays() + " days");
        }
        return occurredAt;
    }
}
