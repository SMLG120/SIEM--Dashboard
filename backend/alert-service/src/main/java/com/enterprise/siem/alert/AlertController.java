package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.SiemAlert;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {
    private final AlertStore alertStore;
    private final AlertRepository alertRepository;

    public AlertController(AlertStore alertStore, AlertRepository alertRepository) {
        this.alertStore = alertStore;
        this.alertRepository = alertRepository;
    }

    @GetMapping
    public List<SiemAlert> listAlerts(@RequestParam(required = false) String status) {
        List<SiemAlert> alerts = alertStore.all();
        if (status == null || status.isBlank()) {
            return alerts;
        }
        AlertStatus filter;
        try {
            filter = AlertStatus.valueOf(status.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown alert status: " + status);
        }
        return alerts.stream().filter(alert -> alert.status() == filter).toList();
    }

    @GetMapping("/{id}")
    public SiemAlert alertById(@PathVariable String id) {
        return alertStore.byId(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    @GetMapping("/{id}/workflow")
    public AlertDetail alertWorkflow(@PathVariable String id) {
        return alertStore.workflow(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    @PostMapping("/{id}/acknowledge")
    public SiemAlert acknowledge(@PathVariable String id) {
        return transition(id, EnumSet.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED), AlertStatus.ACKNOWLEDGED);
    }

    @PostMapping("/{id}/investigate")
    public SiemAlert investigate(@PathVariable String id) {
        return transition(id, EnumSet.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING),
                AlertStatus.INVESTIGATING);
    }

    @PostMapping("/{id}/resolve")
    public SiemAlert resolve(@PathVariable String id) {
        return transition(id, EnumSet.complementOf(EnumSet.of(AlertStatus.RESOLVED)), AlertStatus.RESOLVED);
    }

    @PostMapping("/{id}/reopen")
    public SiemAlert reopen(@PathVariable String id) {
        return transition(id, EnumSet.of(AlertStatus.RESOLVED), AlertStatus.OPEN);
    }

    @PostMapping("/{id}/assign")
    public AlertDetail assign(@PathVariable String id, @Valid @RequestBody AssignRequest request) {
        String assignee = request.assignedTo().trim();
        return alertStore.assign(id, assignee, () -> alertRepository.assign(id, assignee))
                .map(ignored -> alertStore.workflow(id).orElseThrow())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    @PostMapping("/{id}/notes")
    public AlertNote addNote(@PathVariable String id,
                             @Valid @RequestBody AlertNoteRequest request,
                             @AuthenticationPrincipal Jwt jwt) {
        return alertStore.addNote(id, actor(jwt), request.text(), note -> alertRepository.insertNote(id, note))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    private SiemAlert transition(String id, Set<AlertStatus> allowedFrom, AlertStatus status) {
        try {
            return alertStore.transition(id, allowedFrom, status, alertRepository::updateStatus)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
        } catch (AlertStore.InvalidTransitionException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    private String actor(Jwt jwt) {
        if (jwt == null) {
            return "analyst";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? "analyst" : username;
    }
}