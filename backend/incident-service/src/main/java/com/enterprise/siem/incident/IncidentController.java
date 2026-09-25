package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.incident.model.Incident;
import com.enterprise.siem.incident.model.IncidentNote;
import com.enterprise.siem.incident.model.IncidentStatus;
import com.enterprise.siem.incident.model.RelatedAlert;
import com.enterprise.siem.incident.model.TimelineEntry;
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
import java.util.UUID;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {
    private final IncidentStore store;
    private final IncidentRepository repository;

    public IncidentController(IncidentStore store, IncidentRepository repository) {
        this.store = store;
        this.repository = repository;
    }

    @GetMapping
    public List<Incident> listIncidents(@RequestParam(required = false) String status) {
        List<Incident> incidents = store.all();
        if (status == null || status.isBlank()) {
            return incidents;
        }
        IncidentStatus filter;
        try {
            filter = IncidentStatus.valueOf(status.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown incident status: " + status);
        }
        return incidents.stream().filter(incident -> incident.status() == filter).toList();
    }

    @GetMapping("/{id}")
    public Incident incidentById(@PathVariable String id) {
        return store.byId(id)
                .orElseThrow(() -> new NotFoundException("Incident not found: " + id));
    }

    @PostMapping
    public Incident createIncident(@RequestBody CreateIncidentRequest request,
                                   @AuthenticationPrincipal Jwt jwt) {
        if (request.title() == null || request.title().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Incident title is required");
        }
        EventSeverity severity = request.severity() == null ? EventSeverity.MEDIUM : request.severity();
        Incident incident = Incident.create(
                "INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                request.title(),
                request.description() == null ? "" : request.description(),
                severity
        ).appendTimeline(new TimelineEntry(Instant.now(), actor(jwt), "INCIDENT_CREATED",
                "Manually created by " + actor(jwt)));
        store.add(incident);
        repository.save(incident);
        return incident;
    }

    @PatchMapping("/{id}")
    public Incident updateIncident(@PathVariable String id,
                                   @RequestBody UpdateIncidentRequest request,
                                   @AuthenticationPrincipal Jwt jwt) {
        String user = actor(jwt);
        Incident updated = store.update(id, incident -> {
            Incident next = incident;
            if (request.title() != null && !request.title().isBlank()) {
                next = next.withTitle(request.title());
            }
            if (request.description() != null) {
                next = next.withDescription(request.description());
            }
            if (request.severity() != null && request.severity() != incident.severity()) {
                next = next.withSeverity(request.severity())
                        .appendTimeline(new TimelineEntry(Instant.now(), user, "SEVERITY_CHANGED",
                                incident.severity() + " -> " + request.severity()));
            }
            if (request.status() != null && request.status() != incident.status()) {
                next = next.withStatus(request.status())
                        .appendTimeline(new TimelineEntry(Instant.now(), user, "STATUS_CHANGED",
                                incident.status() + " -> " + request.status()));
            }
            if (request.assignedTo() != null && !request.assignedTo().isBlank()
                    && !request.assignedTo().equals(incident.assignedTo())) {
                next = next.withAssignedTo(request.assignedTo())
                        .appendTimeline(new TimelineEntry(Instant.now(), user, "ASSIGNED",
                                "Assigned to " + request.assignedTo()));
            }
            return next;
        }).orElseThrow(() -> new NotFoundException("Incident not found: " + id));
        repository.save(updated);
        return updated;
    }

    @PostMapping("/{id}/notes")
    public IncidentNote addNote(@PathVariable String id,
                                @RequestBody AddNoteRequest request,
                                @AuthenticationPrincipal Jwt jwt) {
        if (request.text() == null || request.text().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Note text is required");
        }
        String user = actor(jwt);
        IncidentNote note = new IncidentNote(
                "NT-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                user,
                request.text(),
                Instant.now()
        );
        store.update(id, incident -> incident
                .appendNote(note)
                .appendTimeline(new TimelineEntry(Instant.now(), user, "NOTE_ADDED", "Note by " + user)))
                .ifPresent(repository::save);
        return note;
    }

    @PostMapping("/{id}/alerts")
    public Incident linkAlert(@PathVariable String id,
                              @RequestBody LinkAlertRequest request,
                              @AuthenticationPrincipal Jwt jwt) {
        if (request.alertId() == null || request.alertId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "alertId is required");
        }
        String user = actor(jwt);
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
        return store.update(id, incident -> {
            if (incident.containsAlert(alert.id())) {
                return incident;
            }
            return incident
                    .appendAlert(alert)
                    .appendTimeline(new TimelineEntry(Instant.now(), user, "ALERT_LINKED",
                            "Linked alert " + alert.id()));
        }).map(persisted -> {
            repository.save(persisted);
            return persisted;
        }).orElseThrow(() -> new NotFoundException("Incident not found: " + id));
    }

    private String actor(Jwt jwt) {
        if (jwt == null) {
            return "system";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? "system" : username;
    }
}