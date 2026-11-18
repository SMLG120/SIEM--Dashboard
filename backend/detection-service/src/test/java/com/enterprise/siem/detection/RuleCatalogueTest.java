package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every packaged rule must ship metadata and examples, and its examples must behave as declared:
 * the {@code match} sequence fires exactly once and the {@code noMatch} sequence never fires.
 */
class RuleCatalogueTest {
    private static final DetectionRuleRepository REPOSITORY = new DetectionRuleRepository(new ObjectMapper());

    static Stream<DetectionRule> rules() {
        return REPOSITORY.all().stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rules")
    void matchExamplesFireExactlyOnce(DetectionRule rule) {
        assertThat(rule.examples().match()).as("%s has match examples", rule.id()).isNotEmpty();
        List<SiemAlert> alerts = RuleTestController.run(rule, RuleTestController.normalize(rule.examples().match(), "m"));
        assertThat(alerts).as("%s match examples", rule.id()).hasSize(1);

        SiemAlert alert = alerts.getFirst();
        assertThat(alert.ruleId()).isEqualTo(rule.id());
        assertThat(alert.ruleVersion()).isEqualTo(rule.version());
        assertThat(alert.mitre()).isEqualTo(rule.mitre());
        assertThat(alert.evidence()).isNotNull();
        assertThat(alert.evidence().matchedConditions()).isNotEmpty();
        assertThat(alert.evidence().eventIds()).isNotEmpty();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rules")
    void noMatchExamplesStaySilent(DetectionRule rule) {
        assertThat(rule.examples().noMatch()).as("%s has non-matching examples", rule.id()).isNotEmpty();
        assertThat(RuleTestController.run(rule, RuleTestController.normalize(rule.examples().noMatch(), "n")))
                .as("%s noMatch examples", rule.id()).isEmpty();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rules")
    void ruleHasDocumentationMetadata(DetectionRule rule) {
        assertThat(rule.id()).matches("SIEM-\\d{4}");
        assertThat(rule.version()).isPositive();
        assertThat(rule.description()).isNotBlank();
        assertThat(rule.falsePositives()).as("%s false-positive notes", rule.id()).isNotEmpty();
        if (!rule.id().equals("SIEM-1006")) { // the catch-all CRITICAL rule maps to no single technique
            assertThat(rule.mitre()).as("%s MITRE mapping", rule.id()).isNotEmpty();
            rule.mitre().forEach(m -> assertThat(m.techniqueId()).matches("T\\d{4}(\\.\\d{3})?"));
        }
    }

    @Test
    void legacyRuleIdsArePreserved() {
        assertThat(REPOSITORY.all()).extracting(DetectionRule::id)
                .contains("SIEM-1001", "SIEM-1002", "SIEM-1003", "SIEM-1004", "SIEM-1005", "SIEM-1006", "SIEM-1007");
    }

    @Test
    void coversEveryRequestedDetectionCategory() {
        List<String> techniques = REPOSITORY.all().stream()
                .flatMap(r -> r.mitre().stream()).map(m -> m.techniqueId()).toList();
        assertThat(techniques).contains(
                "T1110.001",  // brute force
                "T1059.001",  // PowerShell
                "T1068",      // privilege escalation
                "T1046",      // network scanning
                "T1048",      // exfiltration
                "T1071.001",  // C2 beaconing
                "T1204.002",  // malware indicator
                "T1098");     // administrative activity
    }

    /**
     * The seven v1 rules must decide exactly as the v1 engine did. The oracle below is the original
     * v1 matching logic, copied verbatim in behaviour.
     */
    @Test
    void legacyRulesMatchExactlyAsTheV1EngineDid() {
        List<String> types = List.of("MALWARE_DETECTED", "RANSOMWARE_ACTIVITY", "RANSOMWARE", "LOGIN_FAILURE",
                "PRIVILEGE_ESCALATION", "TOR_UNKNOWN", "PORT_SCAN", "SCAN", "DATA_EXFILTRATION", "COMMAND_SHELL",
                "POWERSHELL", "C2_BEACON", "WEBSHELL", "LOGIN_SUCCESS", "CONFIG_CHANGE", "PATCH_APPLIED");
        List<SecurityEvent> events = new ArrayList<>();
        int n = 0;
        for (String type : types) {
            for (EventSeverity severity : EventSeverity.values()) {
                events.add(new SecurityEvent("legacy-" + n++, Instant.parse("2026-01-01T00:00:00Z"), type, severity,
                        "GENERAL", "10.1.1.1", "h", "10.2.2.2", 22, "u", "m"));
            }
        }
        DetectionEngine engine = new DetectionEngine();
        int compared = 0;
        for (DetectionRule rule : REPOSITORY.all()) {
            if (rule.id().compareTo("SIEM-1007") > 0) {
                continue;
            }
            for (SecurityEvent event : events) {
                boolean v2 = !engine.evaluate(event, rule).isEmpty();
                assertThat(v2).as("%s on %s/%s", rule.id(), event.eventType(), event.severity())
                        .isEqualTo(v1Matches(rule.condition(), event));
                compared++;
            }
        }
        assertThat(compared).isEqualTo(7 * events.size());
    }

    private static boolean v1Matches(RuleCondition condition, SecurityEvent event) {
        boolean typeMatches = condition.eventTypes().isEmpty() || condition.eventTypes().contains(event.eventType());
        boolean severityMatches = true;
        if (condition.severityMin() != null && !condition.severityMin().isBlank()) {
            EventSeverity min;
            try {
                min = EventSeverity.valueOf(condition.severityMin().trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                min = EventSeverity.INFO;
            }
            severityMatches = event.severity().ordinal() >= min.ordinal();
        }
        boolean categoryMatches = condition.category() == null || condition.category().isBlank()
                || condition.category().equalsIgnoreCase(event.category());
        return typeMatches && severityMatches && categoryMatches;
    }
}
