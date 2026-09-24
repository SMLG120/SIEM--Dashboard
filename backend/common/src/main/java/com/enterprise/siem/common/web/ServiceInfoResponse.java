package com.enterprise.siem.common.web;

import com.enterprise.siem.common.model.ServiceRole;

import java.time.Instant;

public record ServiceInfoResponse(
        String service,
        ServiceRole role,
        String phase,
        String status,
        Instant timestamp
) {
    public static ServiceInfoResponse ready(String service, ServiceRole role) {
        return new ServiceInfoResponse(service, role, "phase-3", "READY", Instant.now());
    }
}

