package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionEngineTest {
    private static final Instant T0 = Instant.parse("2026-01-15T09:00:00Z");

    private final DetectionEngine engine = new DetectionEngine();

    private static DetectionRule threshold(int count, int window, Integer suppression) {
        return new DetectionRule("TEST-0001", 3, "Brute", "desc", EventSeverity.HIGH, true, RuleType.THRESHOLD,
                new RuleCondition(List.of("LOGIN_FAILURE"), null, null),
                new ThresholdSpec(List.of("sourceIp"), window, count, null, null, null, null),
                null, suppression, List.of(), List.of("fp"), null);
    }

    private static SecurityEvent login(String id, int second, String ip) {
        return new SecurityEvent(id, T0.plusSeconds(second), "LOGIN_FAILURE", EventSeverity.LOW, "AUTH", ip,
                null, null, null, "alice", null);
    }

    @Test
    void singleRuleAlertIdIsDeterministicSoRedeliveryIsIdempotent() {
        DetectionRule rule = new DetectionRule("TEST-0002", "Malware", "d", EventSeverity.CRITICAL, true,
                new RuleCondition(List.of("MALWARE_DETECTED"), null, null));
        SecurityEvent event = new SecurityEvent("evt-1", T0, "MALWARE_DETECTED", EventSeverity.HIGH, null,
                "10.0.0.1", null, null, null, null, null);

        String first = engine.evaluate(event, rule).getFirst().id();
        String redelivered = new DetectionEngine().evaluate(event, rule).getFirst().id();

        assertThat(redelivered).isEqualTo(first);
    }

    @Test
    void thresholdFiresWhenCountReachedWithinWindowAndRecordsEvidence() {
        DetectionRule rule = threshold(3, 60, null);
        assertThat(engine.evaluate(login("a", 0, "1.2.3.4"), rule)).isEmpty();
        assertThat(engine.evaluate(login("b", 10, "1.2.3.4"), rule)).isEmpty();
        List<SiemAlert> alerts = engine.evaluate(login("c", 20, "1.2.3.4"), rule);

        assertThat(alerts).hasSize(1);
        SiemAlert alert = alerts.getFirst();
        assertThat(alert.ruleVersion()).isEqualTo(3);
        assertThat(alert.evidence().eventIds()).containsExactly("a", "b", "c");
        assertThat(alert.evidence().groupKey()).isEqualTo("sourceIp=1.2.3.4");
        assertThat(alert.evidence().firstSeen()).isEqualTo(T0);
        assertThat(alert.evidence().matchedConditions()).anyMatch(c -> c.startsWith("count = 3 >= 3"));
    }

    @Test
    void eventsOutsideTheWindowDoNotCount() {
        DetectionRule rule = threshold(3, 60, null);
        engine.evaluate(login("a", 0, "1.2.3.4"), rule);
        engine.evaluate(login("b", 50, "1.2.3.4"), rule);
        assertThat(engine.evaluate(login("c", 120, "1.2.3.4"), rule)).isEmpty();
    }

    @Test
    void groupsAreIndependent() {
        DetectionRule rule = threshold(2, 60, null);
        engine.evaluate(login("a", 0, "1.1.1.1"), rule);
        assertThat(engine.evaluate(login("b", 1, "2.2.2.2"), rule)).isEmpty();
    }

    @Test
    void redeliveredEventIsNotCountedTwice() {
        DetectionRule rule = threshold(2, 60, null);
        engine.evaluate(login("a", 0, "1.2.3.4"), rule);
        assertThat(engine.evaluate(login("a", 0, "1.2.3.4"), rule)).as("same event again").isEmpty();
    }

    @Test
    void suppressionPreventsAlertStormsForTheSameGroup() {
        DetectionRule rule = threshold(2, 60, 300);
        engine.evaluate(login("a", 0, "1.2.3.4"), rule);
        assertThat(engine.evaluate(login("b", 1, "1.2.3.4"), rule)).hasSize(1);
        assertThat(engine.evaluate(login("c", 2, "1.2.3.4"), rule)).as("suppressed").isEmpty();
        assertThat(engine.evaluate(login("d", 3, "1.2.3.4"), rule)).as("suppressed").isEmpty();
        engine.evaluate(login("e", 400, "1.2.3.4"), rule);
        assertThat(engine.evaluate(login("f", 401, "1.2.3.4"), rule)).as("after suppression").hasSize(1);
    }

    @Test
    void eventsWithoutTheGroupingFieldAreIgnored() {
        DetectionRule rule = threshold(1, 60, null);
        assertThat(engine.evaluate(login("a", 0, null), rule)).isEmpty();
    }

    @Test
    void stateIsBoundedPerRule() {
        DetectionRule rule = threshold(1_000_000, 86_400, null);
        for (int i = 0; i < DetectionEngine.MAX_GROUPS_PER_RULE + 500; i++) {
            engine.evaluate(login("e" + i, i, "10." + (i / 65536) + "." + ((i / 256) % 256) + "." + (i % 256)), rule);
        }
        assertThat(engine.trackedGroups("TEST-0001")).isEqualTo(DetectionEngine.MAX_GROUPS_PER_RULE);
    }

    @Test
    void sequenceRequiresStepsInOrder() {
        DetectionRule rule = new DetectionRule("TEST-0003", 1, "Seq", "d", EventSeverity.CRITICAL, true, RuleType.SEQUENCE,
                null, null,
                new SequenceSpec(List.of("userName"), 600, List.of(
                        new SequenceSpec.Step("fail", new RuleCondition(List.of("LOGIN_FAILURE"), null, null), 2),
                        new SequenceSpec.Step("ok", new RuleCondition(List.of("LOGIN_SUCCESS"), null, null), 1))),
                null, List.of(), List.of("fp"), null);
        SecurityEvent success = new SecurityEvent("s", T0.plusSeconds(30), "LOGIN_SUCCESS", EventSeverity.INFO, null,
                null, null, null, null, "Alice", null);

        engine.evaluate(login("f1", 0, "1.1.1.1"), rule);
        assertThat(engine.evaluate(success, rule)).as("only one failure before success").isEmpty();

        DetectionEngine fresh = new DetectionEngine();
        fresh.evaluate(login("f1", 0, "1.1.1.1"), rule);
        fresh.evaluate(login("f2", 10, "1.1.1.1"), rule);
        List<SiemAlert> alerts = fresh.evaluate(success, rule);
        assertThat(alerts).hasSize(1);
        assertThat(alerts.getFirst().evidence().groupKey()).isEqualTo("userName=alice");
        assertThat(alerts.getFirst().evidence().eventIds()).containsExactly("f1", "f2", "s");
    }

    @Test
    void distinctCountAndSumThresholds() {
        DetectionRule scan = new DetectionRule("TEST-0004", 1, "Scan", "d", EventSeverity.MEDIUM, true, RuleType.THRESHOLD,
                new RuleCondition(List.of("FIREWALL_DENY"), null, null),
                new ThresholdSpec(List.of("sourceIp"), 60, null, "destinationPort", null, 3L, null),
                null, null, List.of(), List.of("fp"), null);
        List<SiemAlert> fired = new ArrayList<>();
        for (int port : new int[]{22, 22, 22, 80}) {
            fired.addAll(engine.evaluate(new SecurityEvent("p" + fired.size() + port + Math.random(), T0, "FIREWALL_DENY",
                    EventSeverity.LOW, null, "9.9.9.9", null, "10.0.0.1", port, null, null), scan));
        }
        assertThat(fired).as("only two distinct ports").isEmpty();
        fired.addAll(engine.evaluate(new SecurityEvent("p443", T0, "FIREWALL_DENY", EventSeverity.LOW, null,
                "9.9.9.9", null, "10.0.0.1", 443, null, null), scan));
        assertThat(fired).hasSize(1);

        DetectionRule exfil = new DetectionRule("TEST-0005", 1, "Exfil", "d", EventSeverity.HIGH, true, RuleType.THRESHOLD,
                new RuleCondition(List.of("NETWORK_FLOW"), null, null, null, null, null, null, true),
                new ThresholdSpec(List.of("sourceIp"), 3600, null, null, "bytesOut", 1000L, null),
                null, null, List.of(), List.of("fp"), null);
        SecurityEvent internal = new SecurityEvent("i1", T0, "NETWORK_FLOW", EventSeverity.INFO, null, "10.0.0.2", null,
                "192.168.1.1", 443, null, null, 2, Map.of("bytesOut", "5000"));
        assertThat(engine.evaluate(internal, exfil)).as("internal destination").isEmpty();
        SecurityEvent external = new SecurityEvent("x1", T0, "NETWORK_FLOW", EventSeverity.INFO, null, "10.0.0.2", null,
                "8.8.8.8", 443, null, null, 2, Map.of("bytesOut", "5000"));
        assertThat(engine.evaluate(external, exfil)).hasSize(1);
    }

    @Test
    void beaconingRequiresRegularIntervals() {
        DetectionRule beacon = new DetectionRule("TEST-0006", 1, "Beacon", "d", EventSeverity.HIGH, true, RuleType.THRESHOLD,
                new RuleCondition(List.of("OUTBOUND_CONNECTION"), null, null),
                new ThresholdSpec(List.of("sourceIp", "destinationIp"), 3600, 5, null, null, null, 0.1),
                null, null, List.of(), List.of("fp"), null);
        List<SiemAlert> regular = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            regular.addAll(engine.evaluate(conn("r" + i, i * 60), beacon));
        }
        assertThat(regular).hasSize(1);
        assertThat(regular.getFirst().evidence().matchedConditions()).anyMatch(c -> c.contains("periodic"));

        DetectionEngine other = new DetectionEngine();
        List<SiemAlert> irregular = new ArrayList<>();
        int[] times = {0, 5, 300, 310, 1200};
        for (int i = 0; i < times.length; i++) {
            irregular.addAll(other.evaluate(conn("x" + i, times[i]), beacon));
        }
        assertThat(irregular).isEmpty();
    }

    private static SecurityEvent conn(String id, int second) {
        return new SecurityEvent(id, T0.plusSeconds(second), "OUTBOUND_CONNECTION", EventSeverity.INFO, null,
                "10.0.0.7", null, "203.0.113.5", 443, null, null);
    }

    @Test
    void disabledRuleStateIsReset() {
        DetectionRule rule = threshold(2, 600, null);
        engine.evaluate(login("a", 0, "1.2.3.4"), rule);
        engine.reset(rule.id());
        assertThat(engine.evaluate(login("b", 1, "1.2.3.4"), rule)).as("old event forgotten").isEmpty();
    }

    private static DetectionRule failuresThenSuccess() {
        return new DetectionRule("TEST-0007", 1, "Seq", "d", EventSeverity.CRITICAL, true, RuleType.SEQUENCE,
                null, null,
                new SequenceSpec(List.of("userName"), 600, List.of(
                        new SequenceSpec.Step("fail", new RuleCondition(List.of("LOGIN_FAILURE"), null, null), 2),
                        new SequenceSpec.Step("ok", new RuleCondition(List.of("LOGIN_SUCCESS"), null, null), 1))),
                null, List.of(), List.of("fp"), null);
    }

    /** Events keyed by id land on different partitions, so the success can be consumed first. */
    @Test
    void sequenceUsesEventTimeWhenTheFinalStepArrivesFirst() {
        DetectionRule rule = failuresThenSuccess();
        SecurityEvent success = new SecurityEvent("s", T0.plusSeconds(30), "LOGIN_SUCCESS", EventSeverity.INFO, null,
                null, null, null, null, "alice", null);

        assertThat(engine.evaluate(success, rule)).as("success alone").isEmpty();
        assertThat(engine.evaluate(login("f1", 0, "1.1.1.1"), rule)).isEmpty();
        List<SiemAlert> alerts = engine.evaluate(login("f2", 10, "1.1.1.1"), rule);

        assertThat(alerts).hasSize(1);
        SiemAlert alert = alerts.getFirst();
        assertThat(alert.eventId()).as("trigger is the success, not the late failure").isEqualTo("s");
        assertThat(alert.evidence().eventIds()).containsExactly("f1", "f2", "s");
        assertThat(alert.evidence().firstSeen()).isEqualTo(T0);
        assertThat(engine.evaluate(login("f3", 20, "1.1.1.1"), rule)).as("same sequence not re-alerted").isEmpty();
    }

    @Test
    void sequenceStillRequiresOrderInEventTime() {
        DetectionRule rule = failuresThenSuccess();
        // Success happened before the failures (in event time): not a brute-force-then-success.
        engine.evaluate(new SecurityEvent("s", T0, "LOGIN_SUCCESS", EventSeverity.INFO, null, null, null, null, null,
                "alice", null), rule);
        engine.evaluate(login("f1", 10, "1.1.1.1"), rule);
        assertThat(engine.evaluate(login("f2", 20, "1.1.1.1"), rule)).isEmpty();
    }

    @Test
    void lateEventsCannotStretchAThresholdWindow() {
        DetectionRule rule = threshold(3, 60, null);
        engine.evaluate(login("a", 1000, "1.2.3.4"), rule);
        engine.evaluate(login("b", 1010, "1.2.3.4"), rule);
        // Arrives late with an event time far outside the window of the newest event.
        assertThat(engine.evaluate(login("old", 0, "1.2.3.4"), rule)).isEmpty();
        assertThat(engine.evaluate(login("c", 1020, "1.2.3.4"), rule)).hasSize(1);
    }
}
