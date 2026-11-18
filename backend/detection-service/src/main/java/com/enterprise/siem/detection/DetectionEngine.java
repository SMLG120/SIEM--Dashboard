package com.enterprise.siem.detection;

import com.enterprise.siem.common.ids.DeterministicIds;
import com.enterprise.siem.common.model.AlertEvidence;
import com.enterprise.siem.common.model.AlertStatus;
import com.enterprise.siem.common.model.EventSeverity;
import com.enterprise.siem.common.model.SecurityEvent;
import com.enterprise.siem.common.model.SiemAlert;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rule evaluation with bounded correlation state.
 *
 * <h2>Alert identity (idempotency)</h2>
 * Alert IDs are derived from their inputs, never random:
 * <ul>
 *   <li>SINGLE: {@code (ruleId, eventId)}. A redelivered event yields the same alert ID.</li>
 *   <li>THRESHOLD/SEQUENCE: {@code (ruleId, groupKey, triggeringEventId)}. Within a process, events
 *   already counted for a group are ignored, so a redelivered event can't count twice.</li>
 * </ul>
 * Downstream inserts are {@code ON CONFLICT DO NOTHING}, which turns duplicates into no-ops.
 *
 * <h2>State limits</h2>
 * Correlation state lives in memory, keyed by rule and group, and uses event time. It is bounded:
 * at most {@value #MAX_GROUPS_PER_RULE} groups per rule (least recently updated evicted first) and at
 * most {@value #MAX_EVENTS_PER_GROUP} events per group. State is lost on restart, and it is exact
 * only when one detection instance sees all of a group's events; that holds for the single-instance
 * deployment but not for a scaled-out consumer group (see docs/architecture.md).
 */
public class DetectionEngine {
    static final int MAX_GROUPS_PER_RULE = 10_000;
    static final int MAX_EVENTS_PER_GROUP = 1_000;

    private final Clock clock;
    private final Map<String, RuleState> states = new ConcurrentHashMap<>();

    public DetectionEngine() {
        this(Clock.systemUTC());
    }

    public DetectionEngine(Clock clock) {
        this.clock = clock;
    }

    public List<SiemAlert> evaluate(SecurityEvent event, DetectionRule rule) {
        return switch (rule.type()) {
            case SINGLE -> evaluateSingle(event, rule).map(List::of).orElse(List.of());
            case THRESHOLD -> state(rule).threshold(event, rule).map(List::of).orElse(List.of());
            case SEQUENCE -> state(rule).sequence(event, rule).map(List::of).orElse(List.of());
        };
    }

    /** Drops correlation state for a rule, e.g. after it is disabled. */
    public void reset(String ruleId) {
        states.remove(ruleId);
    }

    int trackedGroups(String ruleId) {
        RuleState state = states.get(ruleId);
        return state == null ? 0 : state.groups.size();
    }

    private Optional<SiemAlert> evaluateSingle(SecurityEvent event, DetectionRule rule) {
        return ConditionMatcher.match(rule.condition(), event).map(matched -> alert(rule,
                DeterministicIds.of("siem-alert", rule.id(), event.id()),
                event,
                new AlertEvidence(RuleType.SINGLE.name(), matched, List.of(event.id()), 1, null, null,
                        event.timestamp(), event.timestamp())));
    }

    private RuleState state(DetectionRule rule) {
        return states.computeIfAbsent(rule.id(), ignored -> new RuleState());
    }

    private SiemAlert alert(DetectionRule rule, String id, SecurityEvent trigger, AlertEvidence evidence) {
        EventSeverity severity = rule.severity() != null ? rule.severity() : trigger.severity();
        String description = rule.description() != null
                ? rule.description() : "Detection rule " + rule.id() + " matched event " + trigger.eventType();
        return new SiemAlert(id, clock.instant(), rule.id(), rule.name(), description, severity,
                trigger.eventType(), trigger.id(), trigger.sourceIp(), trigger.userName(), AlertStatus.OPEN,
                rule.version(), rule.mitre(), evidence, SiemAlert.CURRENT_SCHEMA_VERSION);
    }

    static String groupKey(List<String> fields, SecurityEvent event) {
        if (fields.isEmpty()) {
            return "*";
        }
        StringBuilder key = new StringBuilder();
        for (String field : fields) {
            String value = field(field, event);
            if (value == null || value.isBlank()) {
                return null; // events missing a grouping field can't be correlated
            }
            if (!key.isEmpty()) {
                key.append(", ");
            }
            key.append(field).append('=').append(value);
        }
        return key.toString();
    }

    static String field(String name, SecurityEvent event) {
        return switch (name) {
            case "sourceIp" -> event.sourceIp();
            case "sourceHost" -> event.sourceHost();
            case "destinationIp" -> event.destinationIp();
            case "destinationPort" -> event.destinationPort() == null ? null : event.destinationPort().toString();
            case "userName" -> event.userName() == null ? null : event.userName().toLowerCase();
            case "eventType" -> event.eventType();
            case "category" -> event.category();
            default -> event.attribute(name);
        };
    }

    private record Hit(Instant at, String eventId, int step, String distinctValue, long amount,
                       List<String> matched) {
    }

    private static final class Group {
        final Deque<Hit> hits = new ArrayDeque<>();
        final Set<String> eventIds = new HashSet<>();
        Instant suppressedUntil = Instant.MIN;

        void add(Hit hit) {
            hits.addLast(hit);
            eventIds.add(hit.eventId());
            while (hits.size() > MAX_EVENTS_PER_GROUP) {
                eventIds.remove(hits.removeFirst().eventId());
            }
        }

        void evictBefore(Instant cutoff) {
            while (!hits.isEmpty() && hits.peekFirst().at().isBefore(cutoff)) {
                eventIds.remove(hits.removeFirst().eventId());
            }
        }
    }

    private final class RuleState {
        /** Access-ordered so the least recently updated group is evicted first. */
        private final LinkedHashMap<String, Group> groups = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Group> eldest) {
                return size() > MAX_GROUPS_PER_RULE;
            }
        };

        synchronized Optional<SiemAlert> threshold(SecurityEvent event, DetectionRule rule) {
            ThresholdSpec spec = Objects.requireNonNull(rule.threshold(), "threshold rule without threshold spec");
            Optional<List<String>> matched = ConditionMatcher.match(rule.condition(), event);
            if (matched.isEmpty() || event.timestamp() == null) {
                return Optional.empty();
            }
            String key = groupKey(spec.groupBy(), event);
            if (key == null) {
                return Optional.empty();
            }
            Group group = groups.computeIfAbsent(key, ignored -> new Group());
            if (group.eventIds.contains(event.id())) {
                return Optional.empty(); // redelivery: already counted
            }
            long amount = 1;
            if (spec.sumAttribute() != null) {
                amount = parseLong(event.attribute(spec.sumAttribute()));
            }
            String distinct = spec.distinctField() == null ? null : field(spec.distinctField(), event);
            group.add(new Hit(event.timestamp(), event.id(), 0, distinct, amount, matched.get()));
            group.evictBefore(event.timestamp().minusSeconds(spec.windowSeconds()));

            if (event.timestamp().isBefore(group.suppressedUntil)) {
                return Optional.empty();
            }

            String measure;
            if (spec.sumAttribute() != null) {
                long sum = group.hits.stream().mapToLong(Hit::amount).sum();
                if (sum < nz(spec.minimum())) {
                    return Optional.empty();
                }
                measure = "sum(" + spec.sumAttribute() + ") = " + sum + " >= " + spec.minimum();
            } else if (spec.distinctField() != null) {
                long distinctCount = group.hits.stream().map(Hit::distinctValue).filter(Objects::nonNull).distinct().count();
                if (distinctCount < nz(spec.minimum())) {
                    return Optional.empty();
                }
                measure = "distinct(" + spec.distinctField() + ") = " + distinctCount + " >= " + spec.minimum();
            } else {
                int required = spec.count() == null ? 1 : spec.count();
                if (group.hits.size() < required) {
                    return Optional.empty();
                }
                measure = "count = " + group.hits.size() + " >= " + required;
            }

            List<String> conditions = new ArrayList<>(matched.get());
            conditions.add(measure + " within " + spec.windowSeconds() + "s by " + key);

            if (spec.maxJitterRatio() != null) {
                Optional<Double> jitter = jitterRatio(group.hits);
                if (jitter.isEmpty() || jitter.get() > spec.maxJitterRatio()) {
                    return Optional.empty();
                }
                conditions.add(String.format("interval jitter %.3f <= %.3f (periodic)", jitter.get(), spec.maxJitterRatio()));
            }

            return Optional.of(fire(rule, key, event, group, conditions, spec.windowSeconds()));
        }

        synchronized Optional<SiemAlert> sequence(SecurityEvent event, DetectionRule rule) {
            SequenceSpec spec = Objects.requireNonNull(rule.sequence(), "sequence rule without sequence spec");
            if (spec.steps().isEmpty() || event.timestamp() == null) {
                return Optional.empty();
            }
            // An event can satisfy at most one step; later steps win so a final step is never swallowed.
            int step = -1;
            List<String> stepMatched = null;
            for (int i = spec.steps().size() - 1; i >= 0; i--) {
                Optional<List<String>> m = ConditionMatcher.match(spec.steps().get(i).condition(), event);
                if (m.isPresent()) {
                    step = i;
                    stepMatched = m.get();
                    break;
                }
            }
            if (step < 0) {
                return Optional.empty();
            }
            String key = groupKey(spec.groupBy(), event);
            if (key == null) {
                return Optional.empty();
            }
            Group group = groups.computeIfAbsent(key, ignored -> new Group());
            if (group.eventIds.contains(event.id())) {
                return Optional.empty();
            }
            group.add(new Hit(event.timestamp(), event.id(), step, null, 1, stepMatched));
            group.evictBefore(event.timestamp().minusSeconds(spec.windowSeconds()));

            int last = spec.steps().size() - 1;
            if (step != last || event.timestamp().isBefore(group.suppressedUntil)) {
                return Optional.empty();
            }

            // Walk hits in arrival order and require each step's count before advancing to the next.
            int current = 0;
            int seen = 0;
            for (Hit hit : group.hits) {
                if (hit.step() == current) {
                    seen++;
                    if (seen >= spec.steps().get(current).requiredCount()) {
                        if (current == last) {
                            break;
                        }
                        current++;
                        seen = 0;
                    }
                }
            }
            boolean complete = current == last && seen >= spec.steps().get(last).requiredCount();
            if (!complete) {
                return Optional.empty();
            }
            List<String> conditions = new ArrayList<>();
            for (SequenceSpec.Step s : spec.steps()) {
                conditions.add("step '" + s.name() + "' x" + s.requiredCount());
            }
            conditions.addAll(stepMatched);
            conditions.add("in order within " + spec.windowSeconds() + "s by " + key);
            return Optional.of(fire(rule, key, event, group, conditions, spec.windowSeconds()));
        }

        private SiemAlert fire(DetectionRule rule, String key, SecurityEvent trigger, Group group,
                               List<String> conditions, int window) {
            group.suppressedUntil = trigger.timestamp().plusSeconds(rule.effectiveSuppressionSeconds());
            List<String> ids = new ArrayList<>();
            for (Iterator<Hit> it = group.hits.iterator(); it.hasNext() && ids.size() < AlertEvidence.MAX_EVENT_IDS; ) {
                ids.add(it.next().eventId());
            }
            AlertEvidence evidence = new AlertEvidence(rule.type().name(), conditions, ids, group.hits.size(), key,
                    window, group.hits.peekFirst().at(), trigger.timestamp());
            return alert(rule, DeterministicIds.of("siem-alert", rule.id(), key, trigger.id()), trigger, evidence);
        }
    }

    /** Coefficient of variation of inter-arrival gaps; needs at least 3 events (2 gaps). */
    static Optional<Double> jitterRatio(Deque<Hit> hits) {
        if (hits.size() < 3) {
            return Optional.empty();
        }
        // Sort by event time: events can arrive slightly out of order.
        List<Instant> times = hits.stream().map(Hit::at).sorted().toList();
        List<Long> gaps = new ArrayList<>();
        for (int i = 1; i < times.size(); i++) {
            gaps.add(Duration.between(times.get(i - 1), times.get(i)).toMillis());
        }
        double mean = gaps.stream().mapToLong(Long::longValue).average().orElse(0);
        if (mean <= 0) {
            return Optional.empty();
        }
        double variance = gaps.stream().mapToDouble(g -> (g - mean) * (g - mean)).sum() / gaps.size();
        return Optional.of(Math.sqrt(variance) / mean);
    }

    private static long parseLong(String value) {
        if (value == null) {
            return 0;
        }
        try {
            return Math.max(0, Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long nz(Long value) {
        return value == null ? 1 : value;
    }
}
