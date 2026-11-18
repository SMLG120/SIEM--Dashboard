package com.enterprise.siem.incident;

import com.enterprise.siem.incident.model.IncidentStatus;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/** Allowed incident status changes. Closing is final except for an explicit reopen. */
final class IncidentWorkflow {
    static final Map<IncidentStatus, Set<IncidentStatus>> NEXT = Map.of(
            IncidentStatus.OPEN, EnumSet.of(IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED,
                    IncidentStatus.RESOLVED, IncidentStatus.CLOSED),
            IncidentStatus.INVESTIGATING, EnumSet.of(IncidentStatus.OPEN, IncidentStatus.CONTAINED,
                    IncidentStatus.RESOLVED, IncidentStatus.CLOSED),
            IncidentStatus.CONTAINED, EnumSet.of(IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED,
                    IncidentStatus.CLOSED),
            IncidentStatus.RESOLVED, EnumSet.of(IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED, IncidentStatus.OPEN),
            IncidentStatus.CLOSED, EnumSet.of(IncidentStatus.OPEN)
    );

    private IncidentWorkflow() {
    }

    static void check(IncidentStatus from, IncidentStatus to) {
        if (from != to && !NEXT.getOrDefault(from, Set.of()).contains(to)) {
            throw new InvalidTransitionException("Cannot move incident from " + from + " to " + to);
        }
    }

    static final class InvalidTransitionException extends RuntimeException {
        InvalidTransitionException(String message) {
            super(message);
        }
    }
}
