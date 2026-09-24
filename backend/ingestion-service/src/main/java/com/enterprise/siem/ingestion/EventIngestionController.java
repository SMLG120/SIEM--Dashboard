package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.SecurityEvent;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/events")
public class EventIngestionController {
    private final EventIngestService ingestService;
    private final EventsStore eventsStore;

    public EventIngestionController(EventIngestService ingestService, EventsStore eventsStore) {
        this.ingestService = ingestService;
        this.eventsStore = eventsStore;
    }

    @GetMapping
    public List<SecurityEvent> listRecent() {
        return eventsStore.recent(200);
    }

    @GetMapping("/{id}")
    public SecurityEvent byId(@PathVariable String id) {
        return eventsStore.byId(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Event not found: " + id));
    }

    @PostMapping
    public ResponseEntity<SecurityEvent> ingest(@Valid @RequestBody IngestEventRequest request) {
        SecurityEvent created = ingestService.ingest(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PostMapping("/batch")
    public ResponseEntity<List<SecurityEvent>> ingestBatch(@Valid @RequestBody List<@Valid IngestEventRequest> requests) {
        List<SecurityEvent> created = requests.stream().map(ingestService::ingest).toList();
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }
}