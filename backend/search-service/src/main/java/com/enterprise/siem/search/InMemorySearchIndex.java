package com.enterprise.siem.search;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

@Component
@ConditionalOnProperty(name = "siem.search.storage", havingValue = "memory", matchIfMissing = true)
class InMemorySearchIndex implements SearchIndex {
    private static final int MAX_DOCS_PER_INDEX = 5000;

    private final Map<String, LinkedHashMap<String, Map<String, Object>>> indexes = new ConcurrentHashMap<>();
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    @Override
    public void index(String indexName, String id, Map<String, Object> document) {
        ReentrantLock lock = locks.computeIfAbsent(indexName, ignored -> new ReentrantLock());
        lock.lock();
        try {
            LinkedHashMap<String, Map<String, Object>> docs = indexes.computeIfAbsent(indexName, ignored -> new LinkedHashMap<>());
            if (docs.containsKey(id)) {
                docs.remove(id);
            }
            docs.put(id, Map.copyOf(document));
            while (docs.size() > MAX_DOCS_PER_INDEX) {
                docs.remove(docs.keySet().iterator().next());
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<SearchHit> recent(String indexName, int limit) {
        return collect(indexName, limit, doc -> true);
    }

    @Override
    public List<SearchHit> search(String indexName, String query, int limit) {
        String needle = query.toLowerCase();
        return collect(indexName, limit, doc -> matches(doc, needle));
    }

    private boolean matches(Map<String, Object> doc, String needle) {
        for (Object value : doc.values()) {
            if (value != null) {
                String text = value instanceof Instant
                        ? value.toString()
                        : String.valueOf(value);
                if (text.toLowerCase().contains(needle)) {
                    return true;
                }
            }
        }
        return false;
    }

    private List<SearchHit> collect(String indexName, int limit, java.util.function.Predicate<Map<String, Object>> predicate) {
        ReentrantLock lock = locks.get(indexName);
        List<SearchHit> hits = new ArrayList<>();
        Map<String, Map<String, Object>> docs = lock == null ? null : snapshot(lock, indexName);
        if (docs != null) {
            List<Map.Entry<String, Map<String, Object>>> entries = new ArrayList<>(docs.entrySet());
            java.util.Collections.reverse(entries);
            for (var entry : entries) {
                if (predicate.test(entry.getValue())) {
                    hits.add(toHit(indexName, entry.getKey(), entry.getValue()));
                }
            }
        }
        return hits.size() > limit ? hits.subList(0, limit) : hits;
    }

    private Map<String, Map<String, Object>> snapshot(ReentrantLock lock, String indexName) {
        lock.lock();
        try {
            LinkedHashMap<String, Map<String, Object>> docs = indexes.get(indexName);
            return docs == null ? Map.of() : new LinkedHashMap<>(docs);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long count(String indexName) {
        ReentrantLock lock = locks.get(indexName);
        if (lock == null) {
            return 0;
        }
        lock.lock();
        try {
            LinkedHashMap<String, Map<String, Object>> docs = indexes.get(indexName);
            return docs == null ? 0 : docs.size();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public Map<String, Long> severityCounts(String indexName) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (SearchHit hit : recent(indexName, MAX_DOCS_PER_INDEX)) {
            Object severity = hit.fields().get("severity");
            if (severity != null) {
                counts.merge(String.valueOf(severity), 1L, Long::sum);
            }
        }
        return counts;
    }

    private SearchHit toHit(String indexName, String id, Map<String, Object> doc) {
        Object timestamp = doc.get("timestamp");
        Instant instant = timestamp instanceof Instant ? (Instant) timestamp
                : timestamp != null ? Instant.parse(String.valueOf(timestamp)) : null;
        return new SearchHit(indexName, id, instant, doc);
    }
}