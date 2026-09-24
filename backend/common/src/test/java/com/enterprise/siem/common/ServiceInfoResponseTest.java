package com.enterprise.siem.common;

import com.enterprise.siem.common.model.ServiceRole;
import com.enterprise.siem.common.web.ServiceInfoResponse;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ServiceInfoResponseTest {
    @Test
    void readyBuildsPhaseThreeResponse() {
        ServiceInfoResponse response = ServiceInfoResponse.ready("ingestion-service", ServiceRole.INGESTION);

        assertThat(response.service()).isEqualTo("ingestion-service");
        assertThat(response.role()).isEqualTo(ServiceRole.INGESTION);
        assertThat(response.phase()).isEqualTo("phase-3");
        assertThat(response.status()).isEqualTo("READY");
        assertThat(response.timestamp()).isNotNull();
    }
}

