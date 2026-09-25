package com.enterprise.siem.search;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    @Override
    public void index(String indexName, String id, Map<String, Object> document) {
        try {
            org.opensearch.client.Request request =
                    new org.opensearch.client.Request("POST", "/" + indexName + "/_doc/" + id);
            request.setJsonEntity(objectMapper.writeValueAsString(document));
            client.performRequest(request);
        } catch (IOException e) {
            log.warn("OpenSearch index failed for {} / {}: {}", indexName, id, e.getMessage());
        }
    }

    @Override
    public List<SearchHit> recent(String indexName, int limit) {
        Map<String, Object> body = Map.of(
                "size", limit,
                "query", Map.of("match_all", Map.of()),
                "sort", List.of(Map.of("timestamp", Map.of("order", "desc")))
        );
        return runSearch(indexName, body);
    }

    @Override
    public List<SearchHit> search(String indexName, String query, int limit) {
        String escaped = query.replaceAll("([+\\-=&|><!(){}\\[\\]^\"~*?:\\\\/])", "\\\\$1");
        Map<String, Object> body = Map.of(
                "size", limit,
                "query", Map.of("query_string", Map.of(
                        "query", "*" + escaped + "*",
                        "fields", List.of("message", "eventType", "severity", "sourceIp", "userName", "ruleName", "status", "category"),
                        "analyze_wildcard", true
                )),
                "sort", List.of(Map.of("timestamp", Map.of("order", "desc")))
        );
        return runSearch(indexName, body);
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
        } catch (IOException e) {
            log.warn("OpenSearch search failed on {}: {}", indexName, e.getMessage());
            return List.of();
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
        } catch (IOException e) {
            return 0;
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
        } catch (IOException e) {
            log.warn("OpenSearch aggregation failed on {}: {}", indexName, e.getMessage());
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