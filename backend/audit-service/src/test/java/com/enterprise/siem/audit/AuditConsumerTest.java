package com.enterprise.siem.audit;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.JdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@JdbcTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({AuditRepository.class, AuditConsumer.class, JacksonAutoConfiguration.class})
class AuditConsumerTest {
    @Autowired
    private AuditConsumer consumer;

    @Autowired
    private AuditRepository repository;

    @Autowired
    private JdbcClient jdbc;

    private static ConsumerRecord<String, String> record(String topic, long offset, String json) {
        return new ConsumerRecord<>(topic, 0, offset, "k", json);
    }

    @Test
    void normalisesRuleAlertAndIncidentRecords() {
        // Real v1 rule-change record (Jackson 2 wrote the instant as epoch-seconds decimal).
        consumer.onRecord(record("siem.rules", 1,
                "{\"ruleId\":\"SIEM-1004\",\"action\":\"DISABLE\",\"severity\":null,\"actor\":\"sam.manager\",\"changedAt\":1794202470.723306553}"));
        consumer.onRecord(record("siem.audit", 1,
                "{\"alertId\":\"A-1\",\"action\":\"RESOLVED\",\"fromStatus\":\"INVESTIGATING\",\"toStatus\":\"RESOLVED\","
                        + "\"actor\":\"sam.analyst\",\"detail\":null,\"occurredAt\":\"2026-11-18T10:00:00Z\"}"));
        consumer.onRecord(record("siem.incidents", 1,
                "{\"incidentId\":\"INC-1\",\"title\":\"t\",\"action\":\"STATUS_CHANGED\",\"at\":\"2026-11-18T11:00:00Z\","
                        + "\"actor\":\"sam.manager\",\"detail\":\"OPEN -> CONTAINED\"}"));

        List<AuditEntry> entries = repository.search(null, null, null, null, 10);
        assertThat(entries).extracting(AuditEntry::action)
                .containsExactly("INCIDENT_STATUS_CHANGED", "ALERT_RESOLVED", "RULE_DISABLE");
        AuditEntry rule = entries.get(2);
        assertThat(rule.actor()).isEqualTo("sam.manager");
        // PostgreSQL TIMESTAMP keeps microseconds.
        assertThat(rule.occurredAt()).isCloseTo(Instant.ofEpochSecond(1794202470L, 723306553), org.assertj.core.api.Assertions.within(1, java.time.temporal.ChronoUnit.MICROS));
        assertThat(entries.get(1).detail()).isEqualTo("INVESTIGATING -> RESOLVED");
        assertThat(repository.search("sam.manager", "INCIDENT", "INC-1", null, 10)).hasSize(1);
    }

    @Test
    void actionsAreNotDoublePrefixed() {
        consumer.onRecord(record("siem.incidents", 20,
                "{\"incidentId\":\"INC-9\",\"action\":\"INCIDENT_CREATED\",\"at\":\"2026-11-18T11:00:00Z\"}"));
        assertThat(repository.search(null, "INCIDENT", "INC-9", null, 10)).extracting(AuditEntry::action)
                .containsExactly("INCIDENT_CREATED");
    }

    @Test
    void redeliveredRecordsAreStoredOnce() {
        String json = "{\"alertId\":\"A-2\",\"action\":\"ASSIGNED\",\"actor\":\"m\",\"occurredAt\":\"2026-11-18T10:00:00Z\"}";
        consumer.onRecord(record("siem.audit", 7, json));
        consumer.onRecord(record("siem.audit", 7, json));
        assertThat(repository.search(null, "ALERT", "A-2", null, 10)).hasSize(1);
    }

    @Test
    void logIsAppendOnlyAndMalformedRecordsAreNotRetried() {
        consumer.onRecord(record("siem.audit", 9, "{\"alertId\":\"A-3\",\"action\":\"X\",\"actor\":\"m\"}"));
        assertThatThrownBy(() -> jdbc.sql("DELETE FROM siem_audit_log").update()).isInstanceOf(Exception.class);
        assertThatThrownBy(() -> consumer.onRecord(record("siem.audit", 10, "not json")))
                .isInstanceOf(com.enterprise.siem.common.kafka.NonRetryableRecordException.class);
    }
}
