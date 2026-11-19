package com.enterprise.siem.detection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * @param groupBy        event fields that form the correlation key (e.g. ["sourceIp"])
 * @param windowSeconds  sliding window, measured on event time
 * @param count          minimum number of matching events (used when distinctField and sumAttribute are null)
 * @param distinctField  if set, count distinct values of this field instead (e.g. "destinationPort" for scans)
 * @param sumAttribute   if set, sum this numeric attribute instead (e.g. "bytesOut" for exfiltration)
 * @param minimum        threshold for distinct counts or sums
 * @param maxJitterRatio if set, additionally require regular timing: stddev/mean of the gaps between
 *                       events must be at or below this (beaconing detection)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ThresholdSpec(
        List<String> groupBy,
        int windowSeconds,
        Integer count,
        String distinctField,
        String sumAttribute,
        Long minimum,
        Double maxJitterRatio
) {
    public ThresholdSpec {
        groupBy = groupBy == null ? List.of() : List.copyOf(groupBy);
    }
}
