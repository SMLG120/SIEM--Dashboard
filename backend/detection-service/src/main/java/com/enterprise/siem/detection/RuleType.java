package com.enterprise.siem.detection;

public enum RuleType {
    /** Fires for every event that matches the condition. */
    SINGLE,
    /** Fires when matching events for one group key cross a count, distinct-count or sum within a window. */
    THRESHOLD,
    /** Fires when ordered steps occur for one group key within a window. */
    SEQUENCE
}
