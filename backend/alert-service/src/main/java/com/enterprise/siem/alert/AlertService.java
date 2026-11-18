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

    private final AlertRepository repository;
    private final Clock clock;

    @org.springframework.beans.factory.annotation.Autowired
    public AlertService(AlertRepository repository) {
        this(repository, Clock.systemUTC());
    }

    AlertService(AlertRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /** Stores an alert from the detection pipeline; redeliveries are no-ops. */
    @Transactional
    public boolean record(SiemAlert alert) {
        boolean created = repository.insert(alert);
        if (created) {
            repository.appendHistory(new AlertHistoryEntry(alert.id(), "CREATED", null, AlertStatus.OPEN,
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
        repository.appendHistory(new AlertHistoryEntry(id, action, from, target, actor, comment, now));
        return repository.findById(id);
    }

    @Transactional
    public Optional<AlertDetail> assign(String id, String assignee, String actor) {
        if (repository.lockStatus(id).isEmpty()) {
            return Optional.empty();
        }
        repository.assign(id, assignee);
        repository.appendHistory(new AlertHistoryEntry(id, "ASSIGNED", null, null, actor,
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
        repository.appendHistory(new AlertHistoryEntry(id, "NOTE_ADDED", null, null, author,
                "Note " + note.id(), note.createdAt()));
        return Optional.of(note);
    }

    public static final class InvalidTransitionException extends RuntimeException {
        public InvalidTransitionException(AlertStatus from, AlertStatus to) {
            super("Cannot move alert from " + from + " to " + to);
        }
    }
}
