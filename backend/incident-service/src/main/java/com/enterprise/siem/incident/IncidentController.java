package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentNote;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {
    static final int MAX_LIST = 200;

    private final IncidentService service;
    private final IncidentRepository repository;

    public IncidentController(IncidentService service, IncidentRepository repository) {
        this.service = service;
        this.repository = repository;
    }

    @GetMapping
    public List<Incident> listIncidents(@RequestParam(required = false) String status,
                                        @RequestParam(defaultValue = "100") int limit) {
        if (limit < 1 || limit > MAX_LIST) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "limit must be 1.." + MAX_LIST);
        }
        IncidentStatus filter = null;
        if (status != null && !status.isBlank()) {
            try {
                filter = IncidentStatus.valueOf(status.trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown incident status");
            }
        }
        return repository.search(filter, limit);
    }

    @GetMapping("/summary")
    public java.util.Map<String, Long> summary() {
        return repository.countByStatus();
    }

    @GetMapping("/{id}")
    public Incident incidentById(@PathVariable String id) {
        return service.findById(id).orElseThrow(() -> new NotFoundException("Incident not found"));
    }

    @PostMapping
    public Incident createIncident(@Valid @RequestBody CreateIncidentRequest request,
                                   @AuthenticationPrincipal Jwt jwt) {
        return service.create(request.title(), request.description(), request.severity(), actor(jwt));
    }

    @PatchMapping("/{id}")
    public Incident updateIncident(@PathVariable String id,
                                   @Valid @RequestBody UpdateIncidentRequest request,
                                   @AuthenticationPrincipal Jwt jwt) {
        try {
            return service.update(id, request, actor(jwt));
        } catch (IncidentWorkflow.InvalidTransitionException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    @PostMapping("/{id}/notes")
    public IncidentNote addNote(@PathVariable String id,
                                @Valid @RequestBody AddNoteRequest request,
                                @AuthenticationPrincipal Jwt jwt) {
        return service.addNote(id, request.text(), actor(jwt));
    }

    @PostMapping("/{id}/alerts")
    public Incident linkAlert(@PathVariable String id,
                              @Valid @RequestBody LinkAlertRequest request,
                              @AuthenticationPrincipal Jwt jwt) {
        EventSeverity severity = request.severity() == null ? EventSeverity.MEDIUM : request.severity();
        RelatedAlert alert = new RelatedAlert(
                request.alertId(),
                request.ruleId() == null ? "MANUAL" : request.ruleId(),
                request.ruleName() == null ? "Manual" : request.ruleName(),
                severity,
                request.eventType() == null ? "UNKNOWN" : request.eventType(),
                request.sourceIp(),
                request.description(),
                Instant.now()
        );
        return service.linkAlert(id, alert, actor(jwt));
    }

    private String actor(Jwt jwt) {
        if (jwt == null) {
            return "system";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? jwt.getSubject() : username;
    }
}
