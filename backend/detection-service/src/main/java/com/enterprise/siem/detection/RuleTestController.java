package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Dry-runs a rule against sample events in an isolated engine: no alerts are published, nothing is
 * stored, and live correlation state is untouched. Analysts use it to check a rule before enabling it.
 */
@RestController
@RequestMapping("/api/rules/test")
public class RuleTestController {
    static final int MAX_EVENTS = 500;

    private final DetectionRuleRepository rules;

    public RuleTestController(DetectionRuleRepository rules) {
        this.rules = rules;
    }

    /**
     * Body: {@code {"ruleId": "SIEM-1008", "events": [...]}} to test a packaged rule, or
     * {@code {"rule": {...}, "events": [...]}} to test a draft definition. If {@code events} is
     * omitted, the rule's own packaged examples are replayed and checked.
     */
    @PostMapping
    public RuleTestResult test(@RequestBody RuleTestRequest request) {
        DetectionRule rule = resolve(request);
        if (request.events() != null && !request.events().isEmpty()) {
            if (request.events().size() > MAX_EVENTS) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At most " + MAX_EVENTS + " events per test");
            }
            return new RuleTestResult(rule.id(), rule.version(), rule.type(), run(rule, normalize(request.events(), "sample")),
                    null, null);
        }
        List<SiemAlert> matchAlerts = run(rule, normalize(rule.examples().match(), "example-match"));
        List<SiemAlert> noMatchAlerts = run(rule, normalize(rule.examples().noMatch(), "example-nomatch"));
        boolean matchOk = rule.examples().match().isEmpty() || matchAlerts.size() == 1;
        boolean noMatchOk = noMatchAlerts.isEmpty();
        return new RuleTestResult(rule.id(), rule.version(), rule.type(), matchAlerts, matchOk && noMatchOk,
                Map.of("matchExamplesFiredOnce", matchOk, "noMatchExamplesSilent", noMatchOk));
    }

    static List<SiemAlert> run(DetectionRule rule, List<SecurityEvent> events) {
        DetectionEngine sandbox = new DetectionEngine();
        DetectionRule enabled = rule.enabled() ? rule : rule.withEnabled(true);
        List<SiemAlert> alerts = new ArrayList<>();
        for (SecurityEvent event : events) {
            alerts.addAll(sandbox.evaluate(event, enabled));
        }
        return alerts;
    }

    /** Fills in IDs and timestamps that sample events usually omit, without changing provided ones. */
    static List<SecurityEvent> normalize(List<SecurityEvent> events, String idPrefix) {
        Instant base = Instant.now().minusSeconds(events.size());
        List<SecurityEvent> out = new ArrayList<>(events.size());
        for (int i = 0; i < events.size(); i++) {
            SecurityEvent e = events.get(i);
            if (e == null || e.eventType() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Event " + i + " needs an eventType");
            }
            out.add(new SecurityEvent(
                    e.id() == null ? idPrefix + "-" + i : e.id(),
                    e.timestamp() == null ? base.plusSeconds(i) : e.timestamp(),
                    e.eventType().toUpperCase(),
                    e.severity() == null ? EventSeverity.INFO : e.severity(),
                    e.category(), e.sourceIp(), e.sourceHost(), e.destinationIp(), e.destinationPort(),
                    e.userName(), e.message(), e.schemaVersion(), e.attributes()));
        }
        return out;
    }

    private DetectionRule resolve(RuleTestRequest request) {
        if (request.rule() != null) {
            try {
                DetectionRuleRepository.validate(request.rule());
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
            }
            return request.rule();
        }
        if (request.ruleId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide ruleId or rule");
        }
        return rules.byId(request.ruleId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rule not found"));
    }

    public record RuleTestRequest(String ruleId, DetectionRule rule, List<SecurityEvent> events) {
    }

    /**
     * @param examplesPassed only set when the packaged examples were replayed
     */
    public record RuleTestResult(String ruleId, int ruleVersion, RuleType ruleType, List<SiemAlert> alerts,
                                 Boolean examplesPassed, Map<String, Boolean> checks) {
    }
}
