package com.enterprise.siem.detection;

import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

@Component
public class DetectionMetrics {
    private final AtomicLong eventsEvaluated = new AtomicLong();
    private final AtomicLong alertsGenerated = new AtomicLong();

    public long incrementEvaluated() {
        return eventsEvaluated.incrementAndGet();
    }

    public long incrementGenerated() {
        return alertsGenerated.incrementAndGet();
    }

    public long eventsEvaluated() {
        return eventsEvaluated.get();
    }

    public long alertsGenerated() {
        return alertsGenerated.get();
    }

    public void reset() {
        eventsEvaluated.set(0);
        alertsGenerated.set(0);
    }
}