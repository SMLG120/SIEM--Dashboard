package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class DetectionMetrics {
    private final MeterRegistry registry;
    private final Counter eventsEvaluated;
    private final Counter alertsGenerated;
    private final Timer detectionLatency;
    private final Map<String, AtomicLong> alertsByRule = new ConcurrentHashMap<>();

    public DetectionMetrics(MeterRegistry meterRegistry) {
        this.registry = meterRegistry;
        this.eventsEvaluated = meterRegistry.counter("siem_detection_events_evaluated_total",
                "component", "detection-engine");
        this.alertsGenerated = meterRegistry.counter("siem_detection_alerts_generated_total",
                "component", "detection-engine");
        // Event time -> alert published. Includes ingestion and Kafka transit, i.e. what an analyst waits for.
        this.detectionLatency = Timer.builder("siem_detection_latency")
                .description("Time from event timestamp to alert publication")
                .publishPercentiles(0.5, 0.95, 0.99)
                .register(meterRegistry);
    }

    public long incrementEvaluated() {
        eventsEvaluated.increment();
        return (long) eventsEvaluated.count();
    }

    public void alertGenerated(SiemAlert alert, SecurityEvent trigger) {
        alertsGenerated.increment();
        registry.counter("siem_detection_rule_alerts_total", "rule", alert.ruleId()).increment();
        alertsByRule.computeIfAbsent(alert.ruleId(), ignored -> new AtomicLong()).incrementAndGet();
        if (trigger.timestamp() != null) {
            Duration latency = Duration.between(trigger.timestamp(), Instant.now());
            if (!latency.isNegative()) {
                detectionLatency.record(latency);
            }
        }
    }

    public long eventsEvaluated() {
        return (long) eventsEvaluated.count();
    }

    public long alertsGenerated() {
        return (long) alertsGenerated.count();
    }

    public Map<String, Long> alertsByRule() {
        Map<String, Long> snapshot = new java.util.TreeMap<>();
        alertsByRule.forEach((rule, count) -> snapshot.put(rule, count.get()));
        return snapshot;
    }

    public double latencyP95Millis() {
        return detectionLatency.takeSnapshot().percentileValues().length > 1
                ? detectionLatency.takeSnapshot().percentileValues()[1].value(java.util.concurrent.TimeUnit.MILLISECONDS)
                : 0;
    }

    public double latencyMeanMillis() {
        return detectionLatency.mean(java.util.concurrent.TimeUnit.MILLISECONDS);
    }
}
