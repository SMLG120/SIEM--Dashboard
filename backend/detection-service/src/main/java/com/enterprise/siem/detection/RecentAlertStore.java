package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

@Component
public class RecentAlertStore {
    private static final int MAX_ALERTS = 100;

    private final List<SiemAlert> alerts = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();

    public void add(SiemAlert alert) {
        lock.lock();
        try {
            if (alerts.size() >= MAX_ALERTS) {
                alerts.remove(alerts.size() - 1);
            }
            alerts.add(0, alert);
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
        lock.lock();
        try {
            return alerts.stream().filter(alert -> alert.id().equals(id)).findFirst();
        } finally {
            lock.unlock();
        }
    }
}