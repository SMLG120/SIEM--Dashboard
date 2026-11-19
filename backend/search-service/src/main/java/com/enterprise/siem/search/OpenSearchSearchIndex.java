package com.enterprise.siem.search;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import org.apache.http.HttpHost;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
@ConditionalOnProperty(name = "siem.search.storage", havingValue = "opensearch")
class OpenSearchSearchIndex implements SearchIndex {
    private static final Logger log = LoggerFactory.getLogger(OpenSearchSearchIndex.class);

    private final RestClient client;
    private final ObjectMapper objectMapper;

    OpenSearchSearchIndex(
            @Value("${siem.search.opensearch.host}") String host,
            @Value("${siem.search.opensearch.port}") int port,
            ObjectMapper objectMapper
    ) {
        this.objectMapper = objectMapper;
        RestClientBuilder builder = RestClient.builder(new HttpHost(host, port, "http"));
        builder.setRequestConfigCallback(config -> config.setConnectTimeout(2000).setSocketTimeout(5000));
        this.client = builder.build();
    }

    /**
     * Explicit mapping, applied when an index is first created. It mirrors what dynamic mapping
     * produced in v1 (text + keyword sub-field, date timestamp) so existing indexes and queries
     * keep working, but turns dynamic mapping off so arbitrary fields can't bloat the mapping.
     */
    static Map<String, Object> mapping() {
        Map<String, Object> textWithKeyword = Map.of("type", "text",
                "fields", Map.of("keyword", Map.of("type", "keyword", "ignore_above", 256)));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("timestamp", Map.of("type", "date"));
        for (String field : List.of("eventType", "severity", "category", "sourceIp", "sourceHost", "destinationIp",
                "userName", "message", "ruleId", "ruleName", "description", "eventId", "status")) {
            properties.put(field, textWithKeyword);
        }
        properties.put("destinationPort", Map.of("type", "long"));
        return Map.of("mappings", Map.of("dynamic", false, "properties", properties));
    }

    @org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
    void ensureIndexes() {
        for (String indexName : List.of(SearchCapture.EVENTS_INDEX, SearchCapture.ALERTS_INDEX)) {
            try {
                if (client.performRequest(new org.opensearch.client.Request("HEAD", "/" + indexName))
                        .getStatusLine().getStatusCode() == 200) {
                    continue;
                }
                org.opensearch.client.Request create = new org.opensearch.client.Request("PUT", "/" + indexName);
                create.setJsonEntity(objectMapper.writeValueAsString(mapping()));
                client.performRequest(create);
                log.info("Created OpenSearch index {} with explicit mapping", indexName);
            } catch (IOException e) {
                // Not fatal: indexing retries later, and the index is then created on first write.
                log.warn("Could not ensure OpenSearch index {}: {}", indexName, e.getMessage());
            }
        }
    }

    /**
     * Fails loudly so the Kafka listener retries and finally dead-letters the record, instead of the
     * document silently never becoming searchable. PUT with the event/alert ID is idempotent.
     */
    @Override
    public void index(String indexName, String id, Map<String, Object> document) {
        try {
            org.opensearch.client.Request request = new org.opensearch.client.Request("PUT",
                    "/" + indexName + "/_doc/" + java.net.URLEncoder.encode(id, java.nio.charset.StandardCharsets.UTF_8));
            request.setJsonEntity(objectMapper.writeValueAsString(document));
            client.performRequest(request);
        } catch (IOException e) {
            throw new SearchUnavailableException("Indexing " + indexName + "/" + id + " failed: " + e.getMessage(), e);
        }
    }

    @Override
    public List<SearchHit> recent(String indexName, int limit) {
        Map<String, Object> body = Map.of(
                "size", limit,
                "query", Map.of("match_all", Map.of()),
                "sort", List.of(Map.of("timestamp", Map.of("order", "desc", "unmapped_type", "date")))
        );
        return runSearch(indexName, body);
    }

    @Override
    public List<SearchHit> search(String indexName, String query, int limit) {
        return runSearch(indexName, searchBody(query, limit));
    }

    /**
     * simple_query_string never throws on user syntax (unlike query_string) and supports quoted
     * phrases, -exclusion and trailing* prefixes; terms are ANDed so extra words narrow results.
     */
    static Map<String, Object> searchBody(String query, int limit) {
        return Map.of(
                "size", limit,
                "query", Map.of("simple_query_string", Map.of(
                        "query", query,
                        "fields", List.of("message", "eventType", "severity", "sourceIp", "sourceHost", "destinationIp",
                                "userName", "ruleId", "ruleName", "description", "status", "category"),
                        "default_operator", "and",
                        "flags", "AND|OR|NOT|PHRASE|PREFIX|WHITESPACE|ESCAPE",
                        "lenient", true
                )),
                "sort", List.of(Map.of("timestamp", Map.of("order", "desc", "unmapped_type", "date")))
        );
    }

    private List<SearchHit> runSearch(String indexName, Map<String, Object> body) {
        try {
            org.opensearch.client.Request request =
                    new org.opensearch.client.Request("POST", "/" + indexName + "/_search");
            request.setJsonEntity(objectMapper.writeValueAsString(body));
            Response response = client.performRequest(request);
            Map<String, Object> parsed = objectMapper.readValue(
                    response.getEntity().getContent(), new TypeReference<>() {
                    });
            return parseHits(indexName, parsed);
        } catch (org.opensearch.client.ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return List.of(); // index not created yet: nothing indexed
            }
            throw new SearchUnavailableException("Search failed on " + indexName, e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Search failed on " + indexName, e);
        }
    }

    private List<SearchHit> parseHits(String indexName, Map<String, Object> parsed) {
        List<SearchHit> hits = new ArrayList<>();
        Map<String, Object> root = castMap(parsed.get("hits"));
        if (root == null) {
            return hits;
        }
        for (Object rawHit : castList(root.get("hits"))) {
            Map<String, Object> hit = castMap(rawHit);
            if (hit == null) {
                continue;
            }
            String id = String.valueOf(hit.get("_id"));
            Map<String, Object> source = castMap(hit.get("_source"));
            if (source == null) {
                continue;
            }
            String timestampText = source.get("timestamp") == null ? null : String.valueOf(source.get("timestamp"));
            Instant timestamp = timestampText == null ? null : Instant.parse(timestampText);
            Map<String, Object> fields = new LinkedHashMap<>(source);
            fields.remove("timestamp");
            hits.add(new SearchHit(indexName, id, timestamp, fields));
        }
        return hits;
    }

    @Override
    public long count(String indexName) {
        try {
            org.opensearch.client.Request request =
                    new org.opensearch.client.Request("GET", "/" + indexName + "/_count");
            Response response = client.performRequest(request);
            Map<String, Object> parsed = objectMapper.readValue(
                    response.getEntity().getContent(), new TypeReference<>() {
                    });
            return ((Number) parsed.get("count")).longValue();
        } catch (org.opensearch.client.ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return 0;
            }
            throw new SearchUnavailableException("Count failed on " + indexName, e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Count failed on " + indexName, e);
        }
    }

    @Override
    public Map<String, Long> severityCounts(String indexName) {
        Map<String, Object> body = Map.of(
                "size", 0,
                "aggs", Map.of("severity", Map.of(
                        "terms", Map.of("field", "severity.keyword", "size", 10)
                ))
        );
        Map<String, Long> counts = new LinkedHashMap<>();
        try {
            org.opensearch.client.Request request =
                    new org.opensearch.client.Request("POST", "/" + indexName + "/_search");
            request.setJsonEntity(objectMapper.writeValueAsString(body));
            Response response = client.performRequest(request);
            Map<String, Object> parsed = objectMapper.readValue(
                    response.getEntity().getContent(), new TypeReference<>() {
                    });
            Map<String, Object> root = castMap(parsed.get("aggregations"));
            if (root != null) {
                Map<String, Object> severityAgg = castMap(root.get("severity"));
                if (severityAgg != null) {
                    for (Object bucket : castList(severityAgg.get("buckets"))) {
                        Map<String, Object> bucketMap = castMap(bucket);
                        if (bucketMap != null) {
                            counts.put(String.valueOf(bucketMap.get("key")),
                                    ((Number) bucketMap.get("doc_count")).longValue());
                        }
                    }
                }
            }
        } catch (org.opensearch.client.ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() != 404) {
                throw new SearchUnavailableException("Aggregation failed on " + indexName, e);
            }
        } catch (IOException e) {
            throw new SearchUnavailableException("Aggregation failed on " + indexName, e);
        }
        return counts;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> castList(Object value) {
        return value instanceof List<?> ? (List<Object>) value : List.of();
    }
}