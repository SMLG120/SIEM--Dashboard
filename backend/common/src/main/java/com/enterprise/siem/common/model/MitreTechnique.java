package com.enterprise.siem.common.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A MITRE ATT&CK reference, e.g. tactic "Credential Access", technique T1110 "Brute Force".
 * {@code url} points at attack.mitre.org for the technique.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record MitreTechnique(String tactic, String techniqueId, String technique) {
    public String url() {
        return techniqueId == null ? null
                : "https://attack.mitre.org/techniques/" + techniqueId.replace('.', '/') + "/";
    }
}
