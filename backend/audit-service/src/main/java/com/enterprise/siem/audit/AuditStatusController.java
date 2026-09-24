package com.enterprise.siem.audit;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AuditStatusController {
    @GetMapping("/api/audit/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("audit-service", ServiceRole.AUDIT);
    }
}

