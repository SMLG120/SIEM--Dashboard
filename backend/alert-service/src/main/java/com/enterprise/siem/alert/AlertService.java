package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Alert workflow. Each operation runs in one transaction that changes the alert and appends the
 * matching history row, so the history can never disagree with the alert's state.
 */
@Service
public class AlertService {
    /** Allowed source states for each target state. */
    static final Map<AlertStatus, Set<AlertStatus>> TRANSITIONS = Map.of(
            AlertStatus.ACKNOWLEDGED, EnumSet.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED),
            AlertStatus.INVESTIGATING, EnumSet.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING),
            AlertStatus.RESOLVED, EnumSet.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING),
            AlertStatus.OPEN, EnumSet.of(AlertStatus.RESOLVED) // reopen
    );

    public static final String AUDIT_TOPIC = "siem.audit";
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(AlertService.class);

    private final AlertRepository repository;
    private final Clock clock;
    private final org.springframework.kafka.core.KafkaTemplate<String, Object> kafka;

    @org.springframework.beans.factory.annotation.Autowired
    public AlertService(AlertRepository repository,
                        org.springframework.beans.factory.ObjectProvider<org.springframework.kafka.core.KafkaTemplate<String, Object>> kafka) {
        this(repository, Clock.systemUTC(), kafka.getIfAvailable());
    }

    AlertService(AlertRepository repository, Clock clock,
                 org.springframework.kafka.core.KafkaTemplate<String, Object> kafka) {
        this.repository = repository;
        this.clock = clock;
        this.kafka = kafka;
    }

    /**
     * Writes the history row in the caller's transaction, then forwards it to the central audit log
     * after commit. siem_alert_history is authoritative; the topic copy is best effort.
     */
    private void history(AlertHistoryEntry entry) {
        repository.appendHistory(entry);
        if (kafka == null || !org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive()) {
            return;
        }
        org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                new org.springframework.transaction.support.TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        try {
                            kafka.send(AUDIT_TOPIC, entry.alertId(), entry);
                        } catch (RuntimeException e) {
                            log.warn("Could not forward alert history to {}: {}", AUDIT_TOPIC, e.getMessage());
                        }
                    }
                });
    }

    /** Stores an alert from the detection pipeline; redeliveries are no-ops. */
    @Transactional
    public boolean record(SiemAlert alert) {
        boolean created = repository.insert(alert);
        if (created) {
            history(new AlertHistoryEntry(alert.id(), "CREATED", null, AlertStatus.OPEN,
                    "detection-service", "Rule " + alert.ruleId() + " v" + alert.ruleVersion(), clock.instant()));
        }
        return created;
    }

    @Transactional
    public Optional<SiemAlert> transition(String id, AlertStatus target, String actor, String comment) {
        Optional<AlertStatus> current = repository.lockStatus(id);
        if (current.isEmpty()) {
            return Optional.empty();
        }
        AlertStatus from = current.get();
        if (!TRANSITIONS.getOrDefault(target, Set.of()).contains(from)) {
            throw new InvalidTransitionException(from, target);
        }
        Instant now = clock.instant();
        if (from != target) {
            repository.updateStatus(id, target, now);
        }
        String action = target == AlertStatus.OPEN ? "REOPENED" : target.name();
        history(new AlertHistoryEntry(id, action, from, target, actor, comment, now));
        return repository.findById(id);
    }

    @Transactional
    public Optional<AlertDetail> assign(String id, String assignee, String actor) {
        if (repository.lockStatus(id).isEmpty()) {
            return Optional.empty();
        }
        repository.assign(id, assignee);
        history(new AlertHistoryEntry(id, "ASSIGNED", null, null, actor,
                "Assigned to " + assignee, clock.instant()));
        return repository.findDetail(id);
    }

    @Transactional
    public Optional<AlertNote> addNote(String id, String author, String text) {
        if (repository.lockStatus(id).isEmpty()) {
            return Optional.empty();
        }
        AlertNote note = new AlertNote("AN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                author, text, clock.instant());
        repository.insertNote(id, note);
        history(new AlertHistoryEntry(id, "NOTE_ADDED", null, null, author,
                "Note " + note.id(), note.createdAt()));
        return Optional.of(note);
    }

    public static final class InvalidTransitionException extends RuntimeException {
        public InvalidTransitionException(AlertStatus from, AlertStatus to) {
            super("Cannot move alert from " + from + " to " + to);
        }
    }
}
