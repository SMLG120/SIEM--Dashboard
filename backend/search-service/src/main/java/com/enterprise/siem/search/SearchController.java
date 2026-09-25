package com.enterprise.siem.search;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/search")
public class SearchController {
    private final SearchIndex index;

    public SearchController(SearchIndex index) {
        this.index = index;
    }

    @GetMapping("/summary")
    public SearchSummary summary() {
        return new SearchSummary(
                index.count(SearchCapture.EVENTS_INDEX),
                index.count(SearchCapture.ALERTS_INDEX),
                index.severityCounts(SearchCapture.EVENTS_INDEX),
                index.severityCounts(SearchCapture.ALERTS_INDEX)
        );
    }

    @GetMapping("/events")
    public List<SearchIndex.SearchHit> searchEvents(
            @RequestParam(defaultValue = "") String q,
            @RequestParam(defaultValue = "50") int limit
    ) {
        return query(SearchCapture.EVENTS_INDEX, q, limit);
    }

    @GetMapping("/alerts")
    public List<SearchIndex.SearchHit> searchAlerts(
            @RequestParam(defaultValue = "") String q,
            @RequestParam(defaultValue = "50") int limit
    ) {
        return query(SearchCapture.ALERTS_INDEX, q, limit);
    }

    private List<SearchIndex.SearchHit> query(String indexName, String q, int limit) {
        int clamped = Math.min(Math.max(limit, 1), 100);
        if (q == null || q.isBlank()) {
            return index.recent(indexName, clamped);
        }
        return index.search(indexName, q.trim(), clamped);
    }

    public record SearchSummary(
            long eventsCount,
            long alertsCount,
            Map<String, Long> eventsBySeverity,
            Map<String, Long> alertsBySeverity
    ) {
    }
}