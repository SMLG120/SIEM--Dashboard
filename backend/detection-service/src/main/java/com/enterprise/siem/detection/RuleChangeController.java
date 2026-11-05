package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

@RestController
@RequestMapping("/api/rules/{id}")
public class RuleChangeController {
    private static final Logger log = LoggerFactory.getLogger(RuleChangeController.class);

    private final RuleChangeService ruleChangeService;

    public RuleChangeController(RuleChangeService ruleChangeService) {
        this.ruleChangeService = ruleChangeService;
    }

    @PostMapping("/enable")
    public DetectionRule enable(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        return change(id, new RuleChange(id, RuleChangeAction.ENABLE, null, actor(jwt), Instant.now()));
    }

    @PostMapping("/disable")
    public DetectionRule disable(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        return change(id, new RuleChange(id, RuleChangeAction.DISABLE, null, actor(jwt), Instant.now()));
    }

    @PostMapping("/severity")
    public DetectionRule setSeverity(@PathVariable String id, @RequestBody SeverityRequest request,
                                     @AuthenticationPrincipal Jwt jwt) {
        EventSeverity severity;
        try {
            severity = EventSeverity.valueOf(request.severity().trim().toUpperCase());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown severity: " + request.severity());
        }
        return change(id, new RuleChange(id, RuleChangeAction.SET_SEVERITY, severity, actor(jwt), Instant.now()));
    }

    private DetectionRule change(String id, RuleChange change) {
        DetectionRule updated = ruleChangeService.applyAndPublish(change)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Rule not found: " + id));
        log.info("AUDIT rule-change rule={} action={} severity={} actor={}",
                change.ruleId(), change.action(), change.severity(), change.actor());
        return updated;
    }

    private static String actor(Jwt jwt) {
        if (jwt == null) {
            return "unknown";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? jwt.getSubject() : username;
    }

    public record SeverityRequest(String severity) {
    }
}