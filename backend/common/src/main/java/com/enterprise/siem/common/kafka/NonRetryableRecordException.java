package com.enterprise.siem.common.kafka;

/**
 * Thrown by a listener for a record that will never process successfully (for example, a payload that is
 * missing required fields). The shared error handler sends it straight to the dead-letter topic without
 * retrying.
 */
public class NonRetryableRecordException extends RuntimeException {
    public NonRetryableRecordException(String message) {
        super(message);
    }
}
