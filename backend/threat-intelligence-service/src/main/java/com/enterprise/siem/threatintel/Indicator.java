package com.enterprise.siem.threatintel;

import com.enterprise.siem.common.model.EventSeverity;

import java.time.Instant;

/**
 * @param source ANALYST (entered by a user) or SIMULATED_DEMO (bundled demo data). The platform has
 *               no external feeds; a feed integration would add its own source value.
 */
public record Indicator(
        String id,
        IndicatorType type,
        String value,
        EventSeverity severity,
        String description,
        String source,
        String createdBy,
        Instant createdAt,
        Instant expiresAt,
        boolean active
) {
    public static final String SOURCE_ANALYST = "ANALYST";
    public static final String SOURCE_SIMULATED_DEMO = "SIMULATED_DEMO";
}
