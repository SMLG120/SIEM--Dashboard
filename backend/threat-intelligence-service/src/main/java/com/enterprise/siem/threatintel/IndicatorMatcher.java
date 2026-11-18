package com.enterprise.siem.threatintel;

import com.enterprise.siem.common.kafka.NonRetryableRecordException;
import com.enterprise.siem.common.model.SecurityEvent;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Checks each event's network and file fields against active indicators and records sightings.
 * Sightings are idempotent per (indicator, event, field), so Kafka redelivery is harmless.
 */
@Component
public class IndicatorMatcher {
    private static final Logger log = LoggerFactory.getLogger(IndicatorMatcher.class);
    /** Event attributes that may carry indicator values. */
    static final List<String> ATTRIBUTE_FIELDS = List.of("fileHash", "sha256", "sha1", "md5", "domain", "dnsQuery", "host");

    private final IndicatorRepository repository;
    private final Clock clock;
    private final Counter sightings;

    @org.springframework.beans.factory.annotation.Autowired
    public IndicatorMatcher(IndicatorRepository repository, MeterRegistry registry) {
        this(repository, registry, Clock.systemUTC());
    }

    IndicatorMatcher(IndicatorRepository repository, MeterRegistry registry, Clock clock) {
        this.repository = repository;
        this.clock = clock;
        this.sightings = registry.counter("siem_threat_intel_sightings_total");
    }

    @KafkaListener(topics = "siem.events", groupId = "threat-intelligence-service")
    @Transactional
    public void onEvent(SecurityEvent event) {
        if (event == null || event.id() == null || event.timestamp() == null) {
            throw new NonRetryableRecordException("event is missing id or timestamp");
        }
        match(event);
    }

    /** @return number of new sightings recorded. */
    int match(SecurityEvent event) {
        Map<String, String> observed = observedValues(event);
        if (observed.isEmpty()) {
            return 0;
        }
        int recorded = 0;
        for (Indicator indicator : repository.matching(observed.values(), clock.instant())) {
            for (Map.Entry<String, String> field : observed.entrySet()) {
                if (field.getValue().equals(indicator.value())
                        && repository.recordSighting(indicator.id(), event.id(), field.getKey(), field.getValue(),
                        event.timestamp(), clock.instant())) {
                    recorded++;
                    sightings.increment();
                    log.info("Indicator {} ({} {}) sighted in event {} field {}", indicator.id(), indicator.type(),
                            indicator.value(), event.id(), field.getKey());
                }
            }
        }
        return recorded;
    }

    static Map<String, String> observedValues(SecurityEvent event) {
        Map<String, String> values = new LinkedHashMap<>();
        put(values, "sourceIp", event.sourceIp());
        put(values, "destinationIp", event.destinationIp());
        for (String attribute : ATTRIBUTE_FIELDS) {
            put(values, attribute, event.attribute(attribute));
        }
        return values;
    }

    private static void put(Map<String, String> values, String field, String value) {
        if (value != null && !value.isBlank() && value.length() <= 256) {
            values.put(field, value.trim().toLowerCase(Locale.ROOT));
        }
    }
}
