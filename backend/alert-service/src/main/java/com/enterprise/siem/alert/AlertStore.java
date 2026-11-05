package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class AlertStore {
    private static final int MAX_ALERTS = 1000;

    private final List<SiemAlert> alerts = new ArrayList<>();
    private final ConcurrentMap<String, SiemAlert> byId = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, String> assignedTo = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, List<AlertNote>> notes = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    public void add(SiemAlert alert) {
        lock.lock();
        try {
            if (byId.containsKey(alert.id())) {
                return; // redelivered Kafka record
            }
            if (alerts.size() >= MAX_ALERTS) {
                SiemAlert evicted = alerts.remove(alerts.size() - 1);
                byId.remove(evicted.id());
                assignedTo.remove(evicted.id());
                notes.remove(evicted.id());
            }
            alerts.add(0, alert);
            byId.put(alert.id(), alert);
        } finally {
            lock.unlock();
        }
    }

    public List<SiemAlert> all() {
        lock.lock();
        try {
            return new ArrayList<>(alerts);
        } finally {
            lock.unlock();
        }
    }

    public Optional<SiemAlert> byId(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    public Optional<SiemAlert> updateStatus(String id, AlertStatus status) {
        return transition(id, EnumSet.allOf(AlertStatus.class), status, ignored -> {
        });
    }

    /**
     * Atomically moves an alert to {@code status} if its current status is in {@code allowedFrom}.
     * {@code persist} runs under the lock before the in-memory state changes, so a failed
     * database write leaves the store untouched.
     */
    public Optional<SiemAlert> transition(String id, Set<AlertStatus> allowedFrom, AlertStatus status,
                                          Consumer<SiemAlert> persist) {
        lock.lock();
        try {
            SiemAlert current = byId.get(id);
            if (current == null) {
                return Optional.empty();
            }
            if (!allowedFrom.contains(current.status())) {
                throw new InvalidTransitionException(current.status(), status);
            }
            SiemAlert updated = current.withStatus(status);
            persist.accept(updated);
            int index = alerts.indexOf(current);
            if (index >= 0) {
                alerts.set(index, updated);
            }
            byId.put(id, updated);
            return Optional.of(updated);
        } finally {
            lock.unlock();
        }
    }

    public Optional<SiemAlert> assign(String id, String analyst) {
        return assign(id, analyst, () -> {
        });
    }

    public Optional<SiemAlert> assign(String id, String analyst, Runnable persist) {
        lock.lock();
        try {
            if (!byId.containsKey(id)) {
                return Optional.empty();
            }
            persist.run();
            assignedTo.put(id, analyst);
            return Optional.of(byId.get(id));
        } finally {
            lock.unlock();
        }
    }

    public Optional<AlertNote> addNote(String id, String author, String text) {
        return addNote(id, author, text, ignored -> {
        });
    }

    public Optional<AlertNote> addNote(String id, String author, String text, Consumer<AlertNote> persist) {
        lock.lock();
        try {
            if (!byId.containsKey(id)) {
                return Optional.empty();
            }
            AlertNote note = new AlertNote(
                    "AN-" + java.util.UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                    author,
                    text,
                    Instant.now()
            );
            persist.accept(note);
            notes.merge(id, new ArrayList<>(List.of(note)), (existing, ignored) ->
                    Stream.concat(existing.stream(), Stream.of(note)).collect(Collectors.toCollection(ArrayList::new)));
            return Optional.of(note);
        } finally {
            lock.unlock();
        }
    }

    public Optional<AlertDetail> workflow(String id) {
        lock.lock();
        try {
            SiemAlert alert = byId.get(id);
            if (alert == null) {
                return Optional.empty();
            }
            return Optional.of(new AlertDetail(
                    alert,
                    assignedTo.get(id),
                    List.copyOf(notes.getOrDefault(id, List.of()))
            ));
        } finally {
            lock.unlock();
        }
    }

    public void restore(List<AlertDetail> details) {
        lock.lock();
        try {
            alerts.clear();
            byId.clear();
            assignedTo.clear();
            notes.clear();
            for (AlertDetail detail : details) {
                alerts.add(detail.alert());
                byId.put(detail.alert().id(), detail.alert());
                if (detail.assignedTo() != null && !detail.assignedTo().isBlank()) {
                    assignedTo.put(detail.alert().id(), detail.assignedTo());
                }
                if (!detail.notes().isEmpty()) {
                    notes.put(detail.alert().id(), new ArrayList<>(detail.notes()));
                }
            }
        } finally {
            lock.unlock();
        }
    }

    public static final class InvalidTransitionException extends RuntimeException {
        public InvalidTransitionException(AlertStatus from, AlertStatus to) {
            super("Cannot move alert from " + from + " to " + to);
        }
    }
}
