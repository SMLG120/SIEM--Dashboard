package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.util.List;

@RestController
@RequestMapping("/api/detection")
public class DetectionSummaryController {
    private final DetectionMetrics metrics;
    private final DetectionRuleRepository ruleRepository;
    private final RecentAlertStore recentAlerts;

    public DetectionSummaryController(
            DetectionMetrics metrics,
            DetectionRuleRepository ruleRepository,
            RecentAlertStore recentAlerts
    ) {
        this.metrics = metrics;
        this.ruleRepository = ruleRepository;
        this.recentAlerts = recentAlerts;
    }

    public record DetectionSummary(
            long eventsEvaluated,
            long alertsGenerated,
            long rulesEnabled,
            List<SiemAlert> recentAlerts
    ) {
    }

    @GetMapping("/summary")
    public DetectionSummary summary() {
        return new DetectionSummary(
                metrics.eventsEvaluated(),
                metrics.alertsGenerated(),
                ruleRepository.enabled().size(),
                recentAlerts.all()
        );
    }

    @GetMapping("/alerts/{id}")
    public SiemAlert alertById(@PathVariable String id) {
        return recentAlerts.byId(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }
}