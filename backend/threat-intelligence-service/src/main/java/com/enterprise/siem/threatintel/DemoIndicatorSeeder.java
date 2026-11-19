package com.enterprise.siem.threatintel;

import com.enterprise.siem.common.model.EventSeverity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * Seeds simulated demo indicators into an empty table when {@code siem.threat-intel.seed-demo=true}.
 * Values are RFC 5737 documentation addresses (never routed on the internet) and the hashes of the
 * harmless EICAR anti-malware test file. They are labelled SIMULATED_DEMO and are not threat intel.
 */
@Component
@ConditionalOnProperty(name = "siem.threat-intel.seed-demo", havingValue = "true")
class DemoIndicatorSeeder implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(DemoIndicatorSeeder.class);

    static final List<Indicator> DEMO = List.of(
            demo("IOC-DEMO-0001", IndicatorType.IP, "203.0.113.140", EventSeverity.HIGH,
                    "Simulated C2 server used by the beaconing demo scenario (RFC 5737 documentation range)."),
            demo("IOC-DEMO-0002", IndicatorType.IP, "198.51.100.23", EventSeverity.MEDIUM,
                    "Simulated password-spraying source in the brute-force demo scenario (RFC 5737)."),
            demo("IOC-DEMO-0003", IndicatorType.IP, "198.51.100.200", EventSeverity.HIGH,
                    "Simulated exfiltration destination in the data-transfer demo scenario (RFC 5737)."),
            demo("IOC-DEMO-0004", IndicatorType.MD5, "44d88612fea8a8f36de82e1278abb02f", EventSeverity.HIGH,
                    "EICAR anti-malware test file (harmless; used to exercise detection end to end)."),
            demo("IOC-DEMO-0005", IndicatorType.SHA256,
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", EventSeverity.HIGH,
                    "EICAR anti-malware test file (harmless; used to exercise detection end to end)."),
            demo("IOC-DEMO-0006", IndicatorType.DOMAIN, "c2.example.net", EventSeverity.HIGH,
                    "Simulated C2 domain (example.net is reserved by RFC 2606)."));

    private final IndicatorRepository repository;

    DemoIndicatorSeeder(IndicatorRepository repository) {
        this.repository = repository;
    }

    private static Indicator demo(String id, IndicatorType type, String value, EventSeverity severity, String description) {
        return new Indicator(id, type, value, severity, description, Indicator.SOURCE_SIMULATED_DEMO, "system",
                Instant.parse("2026-01-01T00:00:00Z"), null, true);
    }

    @Override
    public void run(ApplicationArguments args) {
        if (repository.count() > 0) {
            return;
        }
        int added = 0;
        for (Indicator indicator : DEMO) {
            added += repository.insert(indicator) ? 1 : 0;
        }
        log.info("Seeded {} SIMULATED_DEMO indicators", added);
    }
}
