package com.enterprise.siem.common.ids;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.UUID;

/**
 * Name-based identifiers. The same inputs always produce the same ID, which is what makes Kafka
 * redelivery and client retries idempotent: a re-processed record yields a row that already exists
 * and the {@code INSERT ... ON CONFLICT DO NOTHING} turns it into a no-op.
 *
 * <p>These IDs are identifiers, not secrets or integrity checks; MD5 (UUID v3) is used only for its
 * stable 128-bit spread.
 */
public final class DeterministicIds {
    private static final char SEPARATOR = '\u001F'; // ASCII unit separator: cannot appear in normal input

    private DeterministicIds() {
    }

    public static String of(String namespace, String... parts) {
        Objects.requireNonNull(namespace, "namespace");
        StringBuilder key = new StringBuilder(namespace);
        for (String part : parts) {
            key.append(SEPARATOR).append(part == null ? "" : part);
        }
        return UUID.nameUUIDFromBytes(key.toString().getBytes(StandardCharsets.UTF_8)).toString();
    }
}
