package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.support.serializer.JacksonJsonDeserializer;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Records already on the broker were written by Spring Kafka 3 / Jackson 2, which serialised
 * {@link Instant} as a decimal epoch. {@code siem.rules} is retained forever and replayed on startup,
 * so the Jackson 3 deserializer must keep reading that format.
 */
class KafkaWireCompatibilityTest {

    /** Captured verbatim from the running v1 broker (topic siem.rules). */
    private static final String V1_RULE_CHANGE =
            "{\"ruleId\":\"SIEM-1004\",\"action\":\"DISABLE\",\"severity\":null,"
                    + "\"actor\":\"sam.manager\",\"changedAt\":1794202470.723306553}";

    @Test
    void readsRuleChangeWrittenByJackson2() {
        try (JacksonJsonDeserializer<RuleChange> deserializer = new JacksonJsonDeserializer<>(RuleChange.class)) {
            deserializer.configure(Map.of(JacksonJsonDeserializer.TRUSTED_PACKAGES, "com.enterprise.siem.*"), false);
            RuleChange change = deserializer.deserialize("siem.rules", new RecordHeaders(),
                    V1_RULE_CHANGE.getBytes(StandardCharsets.UTF_8));

            assertThat(change.ruleId()).isEqualTo("SIEM-1004");
            assertThat(change.action()).isEqualTo(RuleChangeAction.DISABLE);
            assertThat(change.actor()).isEqualTo("sam.manager");
            assertThat(change.changedAt()).isEqualTo(Instant.ofEpochSecond(1794202470L, 723306553L));
        }
    }

    @Test
    void readsSecurityEventWithDecimalTimestampAndUnknownFields() {
        String v1Event = "{\"id\":\"e-1\",\"timestamp\":1794202470.5,\"eventType\":\"PORT_SCAN\","
                + "\"severity\":\"MEDIUM\",\"category\":\"NETWORK\",\"sourceIp\":\"10.0.0.5\","
                + "\"destinationPort\":22,\"someFutureField\":true}";
        try (JacksonJsonDeserializer<SecurityEvent> deserializer = new JacksonJsonDeserializer<>(SecurityEvent.class)) {
            SecurityEvent event = deserializer.deserialize("siem.events", new RecordHeaders(),
                    v1Event.getBytes(StandardCharsets.UTF_8));

            assertThat(event.timestamp()).isEqualTo(Instant.ofEpochSecond(1794202470L, 500_000_000L));
            assertThat(event.severity()).isEqualTo(EventSeverity.MEDIUM);
            assertThat(event.destinationPort()).isEqualTo(22);
        }
    }
}
