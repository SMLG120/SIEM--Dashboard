package com.enterprise.siem.detection;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Component;

@Component
public class DetectionMetrics {
    private final Counter eventsEvaluated;
    private final Counter alertsGenerated;

    public DetectionMetrics(MeterRegistry meterRegistry) {
        this.eventsEvaluated = meterRegistry.counter("siem_detection_events_evaluated_total",
                "component", "detection-engine");
        this.alertsGenerated = meterRegistry.counter("siem_detection_alerts_generated_total",
                "component", "detection-engine");
    }

    public long incrementEvaluated() {
        eventsEvaluated.increment();
        return (long) eventsEvaluated.count();
    }

    public long incrementGenerated() {
        alertsGenerated.increment();
        return (long) alertsGenerated.count();
    }

    public long eventsEvaluated() {
        return (long) eventsEvaluated.count();
    }

    public long alertsGenerated() {
        return (long) alertsGenerated.count();
    }

    public void reset() {
        // Micrometer counters are monotonic and cannot be reset; reported values are cumulative.
    }
}