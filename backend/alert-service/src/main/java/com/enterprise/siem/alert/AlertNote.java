package com.enterprise.siem.alert;

import java.time.Instant;

public record AlertNote(
        String id,
        String author,
        String text,
        Instant createdAt
) {
}