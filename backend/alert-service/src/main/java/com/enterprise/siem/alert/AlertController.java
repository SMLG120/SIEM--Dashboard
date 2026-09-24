package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.SiemAlert;
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

import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {
    private final AlertStore alertStore;

    public AlertController(AlertStore alertStore) {
        this.alertStore = alertStore;
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
        return updateStatus(id, AlertStatus.ACKNOWLEDGED);
    }

    @PostMapping("/{id}/investigate")
    public SiemAlert investigate(@PathVariable String id) {
        SiemAlert current = require(id);
        if (current.status() == AlertStatus.RESOLVED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Resolved alerts cannot be investigated; reopen first");
        }
        return updateStatus(id, AlertStatus.INVESTIGATING);
    }

    @PostMapping("/{id}/resolve")
    public SiemAlert resolve(@PathVariable String id) {
        return updateStatus(id, AlertStatus.RESOLVED);
    }

    @PostMapping("/{id}/reopen")
    public SiemAlert reopen(@PathVariable String id) {
        SiemAlert current = require(id);
        if (current.status() != AlertStatus.RESOLVED) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Only resolved alerts can be reopened");
        }
        return updateStatus(id, AlertStatus.OPEN);
    }

    @PostMapping("/{id}/assign")
    public AlertDetail assign(@PathVariable String id, @RequestBody AssignRequest request) {
        if (request.assignedTo() == null || request.assignedTo().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "assignedTo is required");
        }
        return alertStore.assign(id, request.assignedTo())
                .map(ignored -> alertStore.workflow(id).orElseThrow())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    @PostMapping("/{id}/notes")
    public AlertNote addNote(@PathVariable String id,
                             @RequestBody AlertNoteRequest request,
                             @AuthenticationPrincipal Jwt jwt) {
        if (request.text() == null || request.text().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Note text is required");
        }
        return alertStore.addNote(id, actor(jwt), request.text())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    private SiemAlert require(String id) {
        return alertStore.byId(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    private SiemAlert updateStatus(String id, AlertStatus status) {
        return alertStore.updateStatus(id, status)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id));
    }

    private String actor(Jwt jwt) {
        if (jwt == null) {
            return "analyst";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? "analyst" : username;
    }
}