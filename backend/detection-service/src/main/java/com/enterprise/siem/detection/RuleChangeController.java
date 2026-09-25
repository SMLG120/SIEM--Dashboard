package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/rules/{id}")
public class RuleChangeController {
    private final RuleChangeService ruleChangeService;

    public RuleChangeController(RuleChangeService ruleChangeService) {
        this.ruleChangeService = ruleChangeService;
    }

    @PostMapping("/enable")
    public DetectionRule enable(@PathVariable String id) {
        return change(id, new RuleChange(id, RuleChangeAction.ENABLE, null));
    }

    @PostMapping("/disable")
    public DetectionRule disable(@PathVariable String id) {
        return change(id, new RuleChange(id, RuleChangeAction.DISABLE, null));
    }

    @PostMapping("/severity")
    public DetectionRule setSeverity(@PathVariable String id, @RequestBody SeverityRequest request) {
        EventSeverity severity;
        try {
            severity = EventSeverity.valueOf(request.severity().trim().toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown severity: " + request.severity());
        }
        return change(id, new RuleChange(id, RuleChangeAction.SET_SEVERITY, severity));
    }

    private DetectionRule change(String id, RuleChange change) {
        return ruleChangeService.applyAndPublish(change)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rule not found: " + id));
    }

    public record SeverityRequest(String severity) {
    }
}