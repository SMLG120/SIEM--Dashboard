package com.enterprise.siem.search;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface SearchIndex {
    void index(String indexName, String id, Map<String, Object> document);

    List<SearchHit> recent(String indexName, int limit);

    List<SearchHit> search(String indexName, String query, int limit);

    long count(String indexName);

    Map<String, Long> severityCounts(String indexName);

    record SearchHit(String indexName, String id, Instant timestamp, Map<String, Object> fields) {
    }
}