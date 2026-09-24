package com.enterprise.siem.ingestion;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class IngestionStatusController {
    @GetMapping("/api/events/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("ingestion-service", ServiceRole.INGESTION);
    }
}

