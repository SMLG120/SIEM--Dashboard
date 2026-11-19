package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The demo scenario in sample-data/ must trigger every v2 rule except beaconing (which needs real
 * time between events) when ingested as one batch, the way scripts/ingest-demo-events.sh sends it.
 */
class DemoScenarioTest {
    private static final Path SCENARIO = Path.of("../../sample-data/v2-attack-scenario.json");

    @Test
    void batchIngestOfTheScenarioFiresEveryV2RuleButBeaconing() {
        ObjectMapper json = new ObjectMapper();
        List<SecurityEvent> raw = json.readValue(SCENARIO.toFile(), new TypeReference<>() {
        });
        // The ingestion service stamps a batch within milliseconds; mimic that.
        Instant t0 = Instant.parse("2026-11-18T12:00:00Z");
        List<SecurityEvent> events = new ArrayList<>();
        for (int i = 0; i < raw.size(); i++) {
            SecurityEvent e = raw.get(i);
            events.add(new SecurityEvent("demo-" + i, t0.plusMillis(10L * i), e.eventType(),
                    e.severity() == null ? EventSeverity.INFO : e.severity(), e.category(), e.sourceIp(),
                    e.sourceHost(), e.destinationIp(), e.destinationPort(), e.userName(), e.message(),
                    2, e.attributes()));
        }

        List<DetectionRule> rules = new DetectionRuleRepository(json).all().stream().filter(DetectionRule::enabled).toList();
        DetectionEngine engine = new DetectionEngine();
        Set<String> fired = new TreeSet<>();
        for (SecurityEvent event : events) {
            for (DetectionRule rule : rules) {
                engine.evaluate(event, rule).forEach(alert -> fired.add(alert.ruleId()));
            }
        }

        Set<String> expected = new TreeSet<>();
        for (DetectionRule rule : rules) {
            if (rule.id().compareTo("SIEM-1007") > 0 && !rule.id().equals("SIEM-1013")) {
                expected.add(rule.id());
            }
        }
        assertThat(fired).containsAll(expected).doesNotContain("SIEM-1013");
    }
}
