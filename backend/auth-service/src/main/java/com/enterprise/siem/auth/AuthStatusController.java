package com.enterprise.siem.auth;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AuthStatusController {
    @GetMapping("/api/auth/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("auth-service", ServiceRole.AUTH);
    }

    @GetMapping("/api/users/internal/status")
    ServiceInfoResponse usersStatus() {
        return ServiceInfoResponse.ready("auth-service", ServiceRole.AUTH);
    }
}

