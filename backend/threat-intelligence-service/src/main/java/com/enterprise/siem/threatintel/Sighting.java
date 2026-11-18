package com.enterprise.siem.threatintel;

import java.time.Instant;

public record Sighting(String indicatorId, IndicatorType type, String value, String eventId, String field,
                       Instant eventTime, Instant recordedAt) {
}
