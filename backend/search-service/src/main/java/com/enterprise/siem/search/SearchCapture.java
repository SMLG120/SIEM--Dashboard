package com.enterprise.siem.search;

import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class SearchCapture {
    public static final String EVENTS_INDEX = "siem-events";
    public static final String ALERTS_INDEX = "siem-alerts";

    private final SearchIndex index;

    public SearchCapture(SearchIndex index) {
        this.index = index;
    }

    @KafkaListener(topics = "siem.events", groupId = "search-service-events")
    public void onEvent(SecurityEvent event) {
        index.index(EVENTS_INDEX, event.id(), eventAsDocument(event));
    }

    @KafkaListener(topics = "siem.alerts", groupId = "search-service-alerts")
    public void onAlert(SiemAlert alert) {
        index.index(ALERTS_INDEX, alert.id(), alertAsDocument(alert));
    }

    private Map<String, Object> eventAsDocument(SecurityEvent event) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("timestamp", event.timestamp() == null ? null : event.timestamp().toString());
        doc.put("eventType", event.eventType());
        doc.put("severity", event.severity() == null ? null : event.severity().name());
        doc.put("category", event.category());
        doc.put("sourceIp", event.sourceIp());
        doc.put("sourceHost", event.sourceHost());
        doc.put("destinationIp", event.destinationIp());
        doc.put("destinationPort", event.destinationPort());
        doc.put("userName", event.userName());
        doc.put("message", event.message());
        return doc;
    }

    private Map<String, Object> alertAsDocument(SiemAlert alert) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("timestamp", alert.createdAt() == null ? null : alert.createdAt().toString());
        doc.put("ruleId", alert.ruleId());
        doc.put("ruleName", alert.ruleName());
        doc.put("description", alert.description());
        doc.put("severity", alert.severity() == null ? null : alert.severity().name());
        doc.put("eventType", alert.eventType());
        doc.put("eventId", alert.eventId());
        doc.put("sourceIp", alert.sourceIp());
        doc.put("userName", alert.userName());
        doc.put("status", alert.status() == null ? null : alert.status().name());
        return doc;
    }
}