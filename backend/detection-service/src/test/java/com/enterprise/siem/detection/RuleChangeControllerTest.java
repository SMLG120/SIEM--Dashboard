package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;

class RuleChangeControllerTest {
    private final List<RuleChange> published = new ArrayList<>();
    private final RuleChangeController controller = new RuleChangeController(
            new RuleChangeService(new DetectionRuleRepository(new ObjectMapper()), published::add)
    );

    @Test
    void disableThenEnableThroughController() {
        DetectionRule disabled = controller.disable("SIEM-1001");
        Assertions.assertThat(disabled.enabled()).isFalse();
        Assertions.assertThat(published).hasSize(1);
        Assertions.assertThat(published.get(0).action()).isEqualTo(RuleChangeAction.DISABLE);

        DetectionRule reEnabled = controller.enable("SIEM-1001");
        Assertions.assertThat(reEnabled.enabled()).isTrue();
        Assertions.assertThat(published).hasSize(2);
    }

    @Test
    void setSeverityThroughController() {
        DetectionRule updated = controller.setSeverity("SIEM-1005", new RuleChangeController.SeverityRequest("high"));
        Assertions.assertThat(updated.severity()).isEqualTo(EventSeverity.HIGH);
        Assertions.assertThat(published.get(0).severity()).isEqualTo(EventSeverity.HIGH);
    }

    @Test
    void unknownSeverityIsRejected() {
        Assertions.assertThatThrownBy(() ->
                        controller.setSeverity("SIEM-1001", new RuleChangeController.SeverityRequest("bogus")))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        ex -> Assertions.assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void unknownRuleIs404() {
        Assertions.assertThatThrownBy(() -> controller.enable("SIEM-9999"))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        ex -> Assertions.assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
    }
}