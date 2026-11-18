package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SiemAlert;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentNote;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import com.enterprise.siem.incident.model.TimelineEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.UnaryOperator;

/**
 * Incident lifecycle. PostgreSQL is the source of truth: every change locks the incident row,
 * applies the change and appends the timeline entry in one transaction. Notifications on
 * {@code siem.incidents} are sent only after the transaction commits.
 */
@Service
public class IncidentService {
    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final IncidentKafkaConfig kafka;
    private final IncidentRepository repository;

    public IncidentService(IncidentKafkaConfig kafka, IncidentRepository repository) {
        this.kafka = kafka;
        this.repository = repository;
    }

    /**
     * Links the alert to the active incident for its source IP, or opens a new incident.
     * Idempotent: an alert already linked anywhere is ignored. Correlation for one source IP is
     * serialised with an advisory lock so concurrent alerts can't open duplicate incidents.
     */
    @Transactional
    public Optional<Incident> correlate(SiemAlert alert) {
        boolean hasSource = alert.sourceIp() != null && !alert.sourceIp().isBlank();
        repository.lockCorrelationKey(hasSource ? "ip:" + alert.sourceIp() : "alert:" + alert.id());
        if (repository.isAlertLinked(alert.id())) {
            log.debug("Alert {} already linked to an incident", alert.id());
            return Optional.empty();
        }
        RelatedAlert related = toRelated(alert);
        Optional<Incident> active = hasSource ? repository.lockActiveBySourceIp(alert.sourceIp()) : Optional.empty();
        if (active.isPresent()) {
            Incident current = active.get();
            Incident updated = current.appendAlert(related)
                    .appendTimeline(new TimelineEntry(Instant.now(), "system", "ALERT_LINKED",
                            "Linked alert " + alert.id() + " (" + alert.ruleName() + ")"));
            if (alert.severity().ordinal() > current.severity().ordinal()) {
                updated = updated.withSeverity(alert.severity())
                        .appendTimeline(new TimelineEntry(Instant.now(), "system", "SEVERITY_CHANGED",
                                current.severity() + " -> " + alert.severity() + " (linked alert)"));
            }
            repository.save(updated);
            notifyAfterCommit(updated, current.timeline().size());
            return Optional.of(updated);
        }

        Incident created = Incident.create(newId(), buildTitle(alert),
                        "Auto-created from correlated alert " + alert.id() + " (" + alert.ruleName() + ").",
                        alert.severity())
                .appendAlert(related)
                .appendTimeline(new TimelineEntry(Instant.now(), "system", "INCIDENT_CREATED",
                        hasSource ? "Incident created from source " + alert.sourceIp()
                                : "Incident created from alert " + alert.id()));
        repository.save(created);
        log.info("Created incident {} for alert {}", created.id(), alert.id());
        notifyAfterCommit(created, 0);
        return Optional.of(created);
    }

    @Transactional
    public Incident create(String title, String description, EventSeverity severity, String actor) {
        Incident incident = Incident.create(newId(), title, description == null ? "" : description,
                        severity == null ? EventSeverity.MEDIUM : severity)
                .appendTimeline(new TimelineEntry(Instant.now(), actor, "INCIDENT_CREATED", "Manually created by " + actor));
        repository.save(incident);
        notifyAfterCommit(incident, 0);
        return incident;
    }

    @Transactional
    public Incident update(String id, UpdateIncidentRequest request, String actor) {
        return change(id, incident -> {
            Incident next = incident;
            if (request.title() != null && !request.title().isBlank() && !request.title().equals(incident.title())) {
                next = next.withTitle(request.title());
            }
            if (request.description() != null && !request.description().equals(incident.description())) {
                next = next.withDescription(request.description());
            }
            if (request.severity() != null && request.severity() != incident.severity()) {
                next = next.withSeverity(request.severity())
                        .appendTimeline(new TimelineEntry(Instant.now(), actor, "SEVERITY_CHANGED",
                                incident.severity() + " -> " + request.severity()));
            }
            if (request.status() != null && request.status() != incident.status()) {
                IncidentWorkflow.check(incident.status(), request.status());
                next = next.withStatus(request.status())
                        .appendTimeline(new TimelineEntry(Instant.now(), actor, "STATUS_CHANGED",
                                incident.status() + " -> " + request.status()));
            }
            if (request.assignedTo() != null && !request.assignedTo().isBlank()
                    && !request.assignedTo().equals(incident.assignedTo())) {
                next = next.withAssignedTo(request.assignedTo())
                        .appendTimeline(new TimelineEntry(Instant.now(), actor, "ASSIGNED",
                                "Assigned to " + request.assignedTo()));
            }
            return next;
        }, "UPDATED");
    }

    @Transactional
    public Incident updateStatus(String id, IncidentStatus status, String actor) {
        return change(id, current -> {
            IncidentWorkflow.check(current.status(), status);
            return current.status() == status ? current : current.withStatus(status)
                    .appendTimeline(new TimelineEntry(Instant.now(), actor, "STATUS_CHANGED",
                            current.status() + " -> " + status));
        }, "STATUS_CHANGED");
    }

    @Transactional
    public IncidentNote addNote(String id, String text, String actor) {
        IncidentNote note = new IncidentNote("NT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                actor, text, Instant.now());
        change(id, incident -> incident.appendNote(note)
                .appendTimeline(new TimelineEntry(Instant.now(), actor, "NOTE_ADDED", "Note by " + actor)), "NOTE_ADDED");
        return note;
    }

    @Transactional
    public Incident linkAlert(String id, RelatedAlert alert, String actor) {
        return change(id, incident -> incident.containsAlert(alert.id()) ? incident : incident.appendAlert(alert)
                .appendTimeline(new TimelineEntry(Instant.now(), actor, "ALERT_LINKED", "Linked alert " + alert.id())),
                "ALERT_LINKED");
    }

    public Optional<Incident> findById(String id) {
        return repository.findById(id);
    }

    private Incident change(String id, UnaryOperator<Incident> updater, @SuppressWarnings("unused") String action) {
        Incident current = repository.lock(id).orElseThrow(() -> new NotFoundException("Incident not found"));
        Incident updated = updater.apply(current);
        if (updated != current) {
            repository.save(updated);
            notifyAfterCommit(updated, current.timeline().size());
        }
        return updated;
    }

    /** Publishes one event per timeline entry added since {@code previousTimelineSize}, after commit. */
    private void notifyAfterCommit(Incident incident, int previousTimelineSize) {
        List<IncidentEvent> events = incident.timeline().stream().skip(previousTimelineSize)
                .map(t -> new IncidentEvent(incident.id(), incident.title(), t.action(), t.occurredAt(), t.actor(), t.detail()))
                .toList();
        Runnable send = () -> events.forEach(kafka::publish);
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    send.run();
                }
            });
        } else {
            send.run();
        }
    }

    private static String newId() {
        return "INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private static RelatedAlert toRelated(SiemAlert alert) {
        return new RelatedAlert(alert.id(), alert.ruleId(), alert.ruleName(), alert.severity(), alert.eventType(),
                alert.sourceIp(), alert.description(), alert.createdAt());
    }

    private static String buildTitle(SiemAlert alert) {
        if (alert.sourceIp() != null && !alert.sourceIp().isBlank()) {
            return "Suspicious activity from " + alert.sourceIp();
        }
        return alert.ruleName();
    }
}
