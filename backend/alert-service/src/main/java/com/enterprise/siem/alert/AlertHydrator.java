package com.enterprise.siem.alert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class AlertHydrator {
    private static final Logger log = LoggerFactory.getLogger(AlertHydrator.class);
    private static final int HYDRATION_LIMIT = 1000;

    private final AlertRepository repository;
    private final AlertStore store;

    public AlertHydrator(AlertRepository repository, AlertStore store) {
        this.repository = repository;
        this.store = store;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void hydrate() {
        try {
            store.restore(repository.recent(HYDRATION_LIMIT));
            log.info("Restored {} recent alerts from PostgreSQL", store.all().size());
        } catch (Exception e) {
            log.warn("Alert hydration from PostgreSQL failed; continuing with in-memory store: {}", e.getMessage());
        }
    }
}