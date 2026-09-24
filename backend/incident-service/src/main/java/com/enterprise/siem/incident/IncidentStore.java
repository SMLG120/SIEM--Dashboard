package com.enterprise.siem.incident;

import com.enterprise.siem.incident.model.Incident;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

@Component
public class IncidentStore {
    private static final int MAX_INCIDENTS = 100;

    private final List<Incident> incidents = new ArrayList<>();
    private final ConcurrentMap<String, Incident> byId = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    public void add(Incident incident) {
        lock.lock();
        try {
            if (incidents.size() >= MAX_INCIDENTS) {
                Incident evicted = incidents.remove(incidents.size() - 1);
                byId.remove(evicted.id());
            }
            incidents.add(0, incident);
            byId.put(incident.id(), incident);
        } finally {
            lock.unlock();
        }
    }

    public List<Incident> all() {
        lock.lock();
        try {
            return new ArrayList<>(incidents);
        } finally {
            lock.unlock();
        }
    }

    public Optional<Incident> byId(String id) {
        return Optional.ofNullable(byId.get(id));
    }

    public Optional<Incident> update(String id, Function<Incident, Incident> updater) {
        lock.lock();
        try {
            Incident current = byId.get(id);
            if (current == null) {
                return Optional.empty();
            }
            Incident updated = updater.apply(current);
            int index = incidents.indexOf(current);
            if (index >= 0) {
                incidents.set(index, updated);
            }
            byId.put(id, updated);
            return Optional.of(updated);
        } finally {
            lock.unlock();
        }
    }
}