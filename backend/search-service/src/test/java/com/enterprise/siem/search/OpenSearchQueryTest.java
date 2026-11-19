package com.enterprise.siem.search;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OpenSearchQueryTest {
    @Test
    @SuppressWarnings("unchecked")
    void userInputIsPassedAsSimpleQueryStringNotQueryString() {
        Map<String, Object> body = OpenSearchSearchIndex.searchBody("10.0.0.5 AND (x:", 25);
        Map<String, Object> query = (Map<String, Object>) body.get("query");
        assertThat(query).containsOnlyKeys("simple_query_string");
        Map<String, Object> sqs = (Map<String, Object>) query.get("simple_query_string");
        assertThat(sqs.get("query")).isEqualTo("10.0.0.5 AND (x:");
        assertThat(sqs.get("lenient")).isEqualTo(true);
        assertThat(body.get("size")).isEqualTo(25);
    }

    @Test
    @SuppressWarnings("unchecked")
    void mappingKeepsV1KeywordSubfieldsAndDisablesDynamicFields() {
        Map<String, Object> mappings = (Map<String, Object>) OpenSearchSearchIndex.mapping().get("mappings");
        assertThat(mappings.get("dynamic")).isEqualTo(false);
        Map<String, Object> severity = (Map<String, Object>) ((Map<String, Object>) mappings.get("properties")).get("severity");
        assertThat((Map<String, Object>) severity.get("fields")).containsKey("keyword");
    }
}
