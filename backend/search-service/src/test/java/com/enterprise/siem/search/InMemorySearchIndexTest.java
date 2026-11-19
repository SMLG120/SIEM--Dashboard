package com.enterprise.siem.search;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class InMemorySearchIndexTest {
    @Test
    void documentsWithEmptyFieldsAreIndexedAndSearchable() {
        InMemorySearchIndex index = new InMemorySearchIndex();
        Map<String, Object> doc = new HashMap<>();
        doc.put("eventType", "RANSOMWARE_ACTIVITY");
        doc.put("sourceIp", null);
        doc.put("userName", null);

        index.index("siem-events", "e1", doc);

        assertThat(index.search("siem-events", "ransomware", 10)).hasSize(1);
        assertThat(index.recent("siem-events", 10).getFirst().fields()).containsOnlyKeys("eventType");
    }
}
