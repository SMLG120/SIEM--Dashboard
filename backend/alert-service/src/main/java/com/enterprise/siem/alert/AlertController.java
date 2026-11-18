package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
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

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {
    static final int MAX_PAGE_SIZE = 200;
    /** The v1 list endpoint returned the in-memory window; keep a comparable bound. */
    static final int LEGACY_LIST_LIMIT = 500;

    private final AlertRepository repository;
    private final AlertService alertService;

    public AlertController(AlertRepository repository, AlertService alertService) {
        this.repository = repository;
        this.alertService = alertService;
    }

    /** v1-compatible list: newest first, optionally filtered by status. */
    @GetMapping
    public List<SiemAlert> listAlerts(@RequestParam(required = false) String status) {
        List<AlertStatus> statuses = status == null || status.isBlank() ? List.of() : List.of(parse(AlertStatus.class, status));
        return repository.search(new AlertRepository.AlertQuery(statuses, List.of(), null, null, null, null,
                AlertRepository.Sort.CREATED, 0, LEGACY_LIST_LIMIT)).items();
    }

    /** Filtered, paginated queue for the alerts page. */
    @GetMapping("/search")
    public AlertRepository.Page search(
            @RequestParam(required = false) List<String> status,
            @RequestParam(required = false) List<String> severity,
            @RequestParam(required = false) String ruleId,
            @RequestParam(required = false) String assignedTo,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) Instant from,
            @RequestParam(defaultValue = "created") String sort,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        if (page < 0 || page > 10_000 || size < 1 || size > MAX_PAGE_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "page must be 0..10000 and size 1.." + MAX_PAGE_SIZE);
        }
        return repository.search(new AlertRepository.AlertQuery(
                status == null ? List.of() : status.stream().map(s -> parse(AlertStatus.class, s)).toList(),
                severity == null ? List.of() : severity.stream().map(s -> parse(EventSeverity.class, s)).toList(),
                blankToNull(ruleId), blankToNull(assignedTo), blankToNull(sourceIp), from,
                parse(AlertRepository.Sort.class, sort), page, size));
    }

    @GetMapping("/summary")
    public AlertRepository.Summary summary() {
        return repository.summary();
    }

    @GetMapping("/{id}")
    public SiemAlert alertById(@PathVariable String id) {
        return found(repository.findById(id));
    }

    @GetMapping("/{id}/workflow")
    public AlertDetail alertWorkflow(@PathVariable String id) {
        return found(repository.findDetail(id));
    }

    @GetMapping("/{id}/history")
    public List<AlertHistoryEntry> history(@PathVariable String id) {
        found(repository.findById(id));
        return repository.history(id);
    }

    @PostMapping("/{id}/acknowledge")
    public SiemAlert acknowledge(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        return transition(id, AlertStatus.ACKNOWLEDGED, jwt);
    }

    @PostMapping("/{id}/investigate")
    public SiemAlert investigate(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        return transition(id, AlertStatus.INVESTIGATING, jwt);
    }

    @PostMapping("/{id}/resolve")
    public SiemAlert resolve(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        return transition(id, AlertStatus.RESOLVED, jwt);
    }

    @PostMapping("/{id}/reopen")
    public SiemAlert reopen(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
        return transition(id, AlertStatus.OPEN, jwt);
    }

    @PostMapping("/{id}/assign")
    public AlertDetail assign(@PathVariable String id, @Valid @RequestBody AssignRequest request,
                              @AuthenticationPrincipal Jwt jwt) {
        return found(alertService.assign(id, request.assignedTo().trim(), actor(jwt)));
    }

    @PostMapping("/{id}/notes")
    public AlertNote addNote(@PathVariable String id,
                             @Valid @RequestBody AlertNoteRequest request,
                             @AuthenticationPrincipal Jwt jwt) {
        return found(alertService.addNote(id, actor(jwt), request.text()));
    }

    private SiemAlert transition(String id, AlertStatus target, Jwt jwt) {
        try {
            return found(alertService.transition(id, target, actor(jwt), null));
        } catch (AlertService.InvalidTransitionException e) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        }
    }

    private static <T> T found(Optional<T> value) {
        return value.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found"));
    }

    private static <E extends Enum<E>> E parse(Class<E> type, String value) {
        try {
            return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown " + type.getSimpleName() + " value");
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    static String actor(Jwt jwt) {
        if (jwt == null) {
            return "unknown";
        }
        String username = jwt.getClaimAsString("preferred_username");
        return username == null ? jwt.getSubject() : username;
    }
}
