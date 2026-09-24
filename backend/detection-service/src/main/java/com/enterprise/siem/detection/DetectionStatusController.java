package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DetectionStatusController {
    @GetMapping("/api/detection/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("detection-service", ServiceRole.DETECTION);
    }

    @GetMapping("/api/rules/internal/status")
    ServiceInfoResponse rulesStatus() {
        return ServiceInfoResponse.ready("detection-service", ServiceRole.DETECTION);
    }
}

