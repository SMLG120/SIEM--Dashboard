package com.enterprise.siem.ingestion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class EventHydrator {
    private static final Logger log = LoggerFactory.getLogger(EventHydrator.class);
    private static final int HYDRATION_LIMIT = 1000;

    private final EventRepository repository;
    private final EventsStore store;

    public EventHydrator(EventRepository repository, EventsStore store) {
        this.repository = repository;
        this.store = store;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void hydrate() {
        try {
            store.restore(repository.recent(HYDRATION_LIMIT));
            log.info("Restored {} recent events from PostgreSQL", store.recent(HYDRATION_LIMIT).size());
        } catch (Exception e) {
            log.warn("Event hydration from PostgreSQL failed; continuing with in-memory store: {}", e.getMessage());
        }
    }
}