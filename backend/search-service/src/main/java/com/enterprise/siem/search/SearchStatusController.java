package com.enterprise.siem.search;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class SearchStatusController {
    @GetMapping("/api/search/internal/status")
    ServiceInfoResponse status() {
        return ServiceInfoResponse.ready("search-service", ServiceRole.SEARCH);
    }
}