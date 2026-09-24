package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.SecurityEvent;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class EventIngestService {
    public static final String EVENTS_TOPIC = "siem.events";

    private final KafkaTemplate<String, SecurityEvent> kafkaTemplate;
    private final EventsStore eventsStore;

    public EventIngestService(KafkaTemplate<String, SecurityEvent> kafkaTemplate, EventsStore eventsStore) {
        this.kafkaTemplate = kafkaTemplate;
        this.eventsStore = eventsStore;
    }

    public SecurityEvent ingest(IngestEventRequest request) {
        SecurityEvent event = new SecurityEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                request.eventType().trim().toUpperCase(),
                request.severity(),
                request.effectiveCategory(),
                request.sourceIp(),
                request.sourceHost(),
                request.destinationIp(),
                request.destinationPort(),
                request.userName(),
                request.message()
        );
        eventsStore.add(event);
        kafkaTemplate.send(EVENTS_TOPIC, event.id(), event);
        return event;
    }
}