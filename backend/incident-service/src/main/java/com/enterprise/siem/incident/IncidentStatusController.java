package com.enterprise.siem.incident;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class IncidentStatusController {
    @GetMapping("/api/incidents/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("incident-service", ServiceRole.INCIDENT);
    }
}

