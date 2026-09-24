package com.enterprise.siem.alert;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AlertStatusController {
    @GetMapping("/api/alerts/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("alert-service", ServiceRole.ALERT);
    }
}

