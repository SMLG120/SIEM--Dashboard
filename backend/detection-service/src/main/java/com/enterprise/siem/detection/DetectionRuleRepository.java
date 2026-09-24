package com.enterprise.siem.detection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;

@Repository
public class DetectionRuleRepository {
    private final List<DetectionRule> rules;

    public DetectionRuleRepository(ObjectMapper objectMapper) {
        try (InputStream in = getClass().getResourceAsStream("/detection-rules.json")) {
            this.rules = objectMapper.readValue(in, new TypeReference<>() {
            });
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load detection rules", e);
        }
    }

    public List<DetectionRule> all() {
        return rules;
    }

    public List<DetectionRule> enabled() {
        return rules.stream().filter(DetectionRule::enabled).toList();
    }

    public Optional<DetectionRule> byId(String id) {
        return rules.stream().filter(rule -> rule.id().equals(id)).findFirst();
    }
}