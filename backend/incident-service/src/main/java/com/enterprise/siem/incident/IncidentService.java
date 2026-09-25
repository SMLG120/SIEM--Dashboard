package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.SiemAlert;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import com.enterprise.siem.incident.model.TimelineEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Comparator;
import java.util.Optional;
import java.util.UUID;

@Service
public class IncidentService {
    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final IncidentStore store;
    private final IncidentKafkaConfig kafka;
    private final IncidentRepository repository;

    public IncidentService(IncidentStore store, IncidentKafkaConfig kafka, IncidentRepository repository) {
        this.store = store;
        this.kafka = kafka;
        this.repository = repository;
    }

    public void correlate(SiemAlert alert) {
        Optional<Incident> matched = findCorrelated(alert);
        if (matched.isPresent()) {
            Incident incident = matched.get();
            if (incident.containsAlert(alert.id())) {
                log.debug("Alert {} already linked to incident {}", alert.id(), incident.id());
                return;
            }
            RelatedAlert related = toRelated(alert);
            Incident updated = store.update(incident.id(), current -> current
                            .appendAlert(related)
                            .appendTimeline(new TimelineEntry(
                                    Instant.now(),
                                    "system",
                                    "ALERT_LINKED",
                                    "Linked alert " + alert.id() + " (" + alert.ruleName() + ")")))
                    .orElse(incident);
            repository.save(updated);
            kafka.publish(updated.id(), updated.title(), "ALERT_LINKED");
            return;
        }

        Incident created = Incident.create(
                "INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                buildTitle(alert),
                "Auto-created from correlated alert " + alert.id() + " (" + alert.ruleName() + ").",
                alert.severity()
        );
        Incident withAlert = created
                .appendAlert(toRelated(alert))
                .appendTimeline(new TimelineEntry(Instant.now(), "system", "INCIDENT_CREATED",
                        "Incident created from source " + alert.sourceIp()));
        store.add(withAlert);
        repository.save(withAlert);
        log.info("Created incident {} for alert {}", withAlert.id(), alert.id());
        kafka.publish(withAlert.id(), withAlert.title(), "INCIDENT_CREATED");
    }

    private Optional<Incident> findCorrelated(SiemAlert alert) {
        if (alert.sourceIp() == null || alert.sourceIp().isBlank()) {
            return Optional.empty();
        }
        return store.all().stream()
                .filter(Incident::isActive)
                .filter(incident -> incident.relatedAlerts().stream()
                        .anyMatch(related -> alert.sourceIp().equals(related.sourceIp())))
                .max(Comparator.comparing(Incident::updatedAt));
    }

    private RelatedAlert toRelated(SiemAlert alert) {
        return new RelatedAlert(
                alert.id(),
                alert.ruleId(),
                alert.ruleName(),
                alert.severity(),
                alert.eventType(),
                alert.sourceIp(),
                alert.description(),
                alert.createdAt()
        );
    }

    private String buildTitle(SiemAlert alert) {
        if (alert.sourceIp() != null && !alert.sourceIp().isBlank()) {
            return "Suspicious activity from " + alert.sourceIp();
        }
        return alert.ruleName();
    }

    public Optional<Incident> findById(String id) {
        return store.byId(id);
    }

    public Incident updateStatus(String id, IncidentStatus status, String actor) {
        Incident updated = store.update(id, current -> {
            Incident next = current.withStatus(status);
            TimelineEntry entry = new TimelineEntry(Instant.now(), actor, "STATUS_CHANGED",
                    current.status() + " -> " + status);
            return next.appendTimeline(entry);
        }).orElseThrow(() -> new com.enterprise.siem.incident.NotFoundException("Incident not found: " + id));
        repository.save(updated);
        return updated;
    }
}