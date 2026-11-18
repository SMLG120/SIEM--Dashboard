package com.enterprise.siem.threatintel;

import com.enterprise.siem.common.model.EventSeverity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/threat-intel")
public class ThreatIntelController {
    private final IndicatorRepository repository;

    public ThreatIntelController(IndicatorRepository repository) {
        this.repository = repository;
    }

    public record CreateIndicatorRequest(
            @NotNull IndicatorType type,
            @NotNull @Size(max = 256) String value,
            EventSeverity severity,
            @Size(max = 1000) String description,
            Instant expiresAt) {
    }

    @GetMapping("/indicators")
    public List<Indicator> indicators(@RequestParam(defaultValue = "true") boolean activeOnly,
                                      @RequestParam(defaultValue = "200") int limit) {
        return repository.list(activeOnly, clamp(limit));
    }

    @GetMapping("/indicators/{id}")
    public Indicator indicator(@PathVariable String id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Indicator not found"));
    }

    /** Manually entered indicators are always recorded with source ANALYST and the caller as author. */
    @PostMapping("/indicators")
    @ResponseStatus(HttpStatus.CREATED)
    public Indicator create(@Valid @RequestBody CreateIndicatorRequest request, @AuthenticationPrincipal Jwt jwt) {
        String value;
        try {
            value = request.type().canonical(request.value());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
        if (request.expiresAt() != null && !request.expiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "expiresAt must be in the future");
        }
        Indicator indicator = new Indicator("IOC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
                request.type(), value, request.severity() == null ? EventSeverity.MEDIUM : request.severity(),
                request.description(), Indicator.SOURCE_ANALYST, actor(jwt), Instant.now(), request.expiresAt(), true);
        if (!repository.insert(indicator)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Indicator already exists");
        }
        return indicator;
    }

    /** Deactivates rather than deletes, so past sightings keep their context. */
    @DeleteMapping("/indicators/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deactivate(@PathVariable String id) {
        if (!repository.deactivate(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Active indicator not found");
        }
    }

    @GetMapping("/sightings")
    public List<Sighting> sightings(@RequestParam(required = false) String indicatorId,
                                    @RequestParam(defaultValue = "100") int limit) {
        return repository.sightings(indicatorId, clamp(limit));
    }

    /** Checks one value against active indicators, e.g. while triaging an alert. */
    @GetMapping("/lookup")
    public List<Indicator> lookup(@RequestParam @Size(max = 256) String value) {
        return repository.matching(List.of(value.trim().toLowerCase(java.util.Locale.ROOT)), Instant.now());
    }

    private static int clamp(int limit) {
        return Math.min(Math.max(limit, 1), 500);
    }

    private static String actor(Jwt jwt) {
        if (jwt == null) {
            return "unknown";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? jwt.getSubject() : username;
    }
}
