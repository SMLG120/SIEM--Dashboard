package com.enterprise.siem.detection;

import com.enterprise.siem.common.model.EventSeverity;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionRuleRepositoryTest {
    private final DetectionRuleRepository repository = new DetectionRuleRepository(new ObjectMapper());

    @Test
    void loadsBundledRules() {
        assertThat(repository.all())
                .extracting(DetectionRule::id)
                .contains("SIEM-1001", "SIEM-1007");
        assertThat(repository.enabled()).isNotEmpty();
    }

    @Test
    void disablesRuleAndReenablesIt() {
        assertThat(repository.byId("SIEM-1001")).map(DetectionRule::enabled).contains(true);

        repository.apply(new RuleChange("SIEM-1001", RuleChangeAction.DISABLE, null));
        assertThat(repository.byId("SIEM-1001")).map(DetectionRule::enabled).contains(false);

        repository.apply(new RuleChange("SIEM-1001", RuleChangeAction.ENABLE, null));
        assertThat(repository.byId("SIEM-1001")).map(DetectionRule::enabled).contains(true);
    }

    @Test
    void changesSeverity() {
        DetectionRule updated = repository
                .apply(new RuleChange("SIEM-1001", RuleChangeAction.SET_SEVERITY, EventSeverity.HIGH))
                .orElseThrow();

        assertThat(updated.severity()).isEqualTo(EventSeverity.HIGH);
        assertThat(repository.byId("SIEM-1001")).map(DetectionRule::severity).contains(EventSeverity.HIGH);
    }

    @Test
    void unknownRuleReturnsEmpty() {
        assertThat(repository.apply(new RuleChange("SIEM-9999", RuleChangeAction.ENABLE, null))).isEmpty();
    }
}