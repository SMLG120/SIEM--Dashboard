package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.validation.IpAddress;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

@RestController
@RequestMapping("/api/events")
public class EventIngestionController {
    static final int MAX_BATCH_SIZE = 500;
    static final int MAX_PAGE_SIZE = 500;

    private final EventIngestService ingestService;
    private final EventRepository events;

    public EventIngestionController(EventIngestService ingestService, EventRepository events) {
        this.ingestService = ingestService;
        this.events = events;
    }

    /**
     * Newest-first page of events. For the next page pass the last item's {@code timestamp} and
     * {@code id} as {@code beforeTimestamp} and {@code beforeId}.
     */
    @GetMapping
    public List<SecurityEvent> list(
            @RequestParam(defaultValue = "200") @Min(1) @Max(MAX_PAGE_SIZE) int limit,
            @RequestParam(required = false) EventSeverity severity,
            @RequestParam(required = false) @Size(max = 64) String eventType,
            @RequestParam(required = false) @IpAddress String sourceIp,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant beforeTimestamp,
            @RequestParam(required = false) @Size(max = 64) String beforeId) {
        if ((beforeTimestamp == null) != (beforeId == null)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "beforeTimestamp and beforeId go together");
        }
        EventRepository.Cursor cursor = beforeTimestamp == null ? null : new EventRepository.Cursor(beforeTimestamp, beforeId);
        return events.search(new EventRepository.EventQuery(severity,
                eventType == null || eventType.isBlank() ? null : eventType.trim().toUpperCase(),
                sourceIp, from, to, cursor, limit));
    }

    @GetMapping("/{id}")
    public SecurityEvent byId(@PathVariable @Size(max = 64) String id) {
        return events.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Event not found"));
    }

    @PostMapping
    public ResponseEntity<SecurityEvent> ingest(@Valid @RequestBody IngestEventRequest request,
                                                @AuthenticationPrincipal Jwt jwt) {
        SecurityEvent created = ingestService.ingest(request, clientId(jwt));
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PostMapping("/batch")
    public ResponseEntity<List<SecurityEvent>> ingestBatch(@RequestBody List<@Valid IngestEventRequest> requests,
                                                           @AuthenticationPrincipal Jwt jwt) {
        if (requests == null || requests.isEmpty() || requests.size() > MAX_BATCH_SIZE) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Batch must contain between 1 and " + MAX_BATCH_SIZE + " events");
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(ingestService.ingestBatch(requests, clientId(jwt)));
    }

    /** Idempotency keys are scoped per authenticated caller (Keycloak subject). */
    private static String clientId(Jwt jwt) {
        return jwt == null ? "anonymous" : jwt.getSubject();
    }
}
