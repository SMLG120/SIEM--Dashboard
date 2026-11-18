package com.enterprise.siem.audit;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/audit")
public class AuditController {
    private final AuditRepository repository;

    public AuditController(AuditRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/events")
    public List<AuditEntry> events(@RequestParam(required = false) String actor,
                                   @RequestParam(required = false) String resourceType,
                                   @RequestParam(required = false) String resourceId,
                                   @RequestParam(required = false) Instant from,
                                   @RequestParam(defaultValue = "100") int limit) {
        return repository.search(blank(actor), blank(resourceType), blank(resourceId), from,
                Math.min(Math.max(limit, 1), 500));
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
