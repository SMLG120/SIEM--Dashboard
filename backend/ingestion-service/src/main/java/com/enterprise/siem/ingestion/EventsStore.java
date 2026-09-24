package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;

@Component
public class EventsStore {
    private static final int MAX_EVENTS = 1000;

    private final Deque<SecurityEvent> events = new ArrayDeque<>();
    private final ConcurrentMap<String, SecurityEvent> byId = new ConcurrentHashMap<>();
    private final ReentrantLock lock = new ReentrantLock();

    public void add(SecurityEvent event) {
        lock.lock();
        try {
            if (events.size() >= MAX_EVENTS) {
                SecurityEvent evicted = events.removeLast();
                byId.remove(evicted.id());
            }
            events.addFirst(event);
            byId.put(event.id(), event);
        } finally {
            lock.unlock();
        }
    }

    public List<SecurityEvent> recent(int limit) {
        lock.lock();
        try {
            int size = Math.min(limit, events.size());
            return new ArrayList<>(events.stream().limit(size).toList());
        } finally {
            lock.unlock();
        }
    }

    public Optional<SecurityEvent> byId(String id) {
        return Optional.ofNullable(byId.get(id));
    }
}