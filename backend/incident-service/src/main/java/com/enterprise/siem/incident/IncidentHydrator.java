package com.enterprise.siem.incident;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class IncidentHydrator {
    private static final Logger log = LoggerFactory.getLogger(IncidentHydrator.class);
    private static final int HYDRATION_LIMIT = 100;

    private final IncidentRepository repository;
    private final IncidentStore store;

    public IncidentHydrator(IncidentRepository repository, IncidentStore store) {
        this.repository = repository;
        this.store = store;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void hydrate() {
        try {
            store.restore(repository.recent(HYDRATION_LIMIT));
            log.info("Restored {} recent incidents from PostgreSQL", store.all().size());
        } catch (Exception e) {
            log.warn("Incident hydration from PostgreSQL failed; continuing with in-memory store: {}", e.getMessage());
        }
    }
}