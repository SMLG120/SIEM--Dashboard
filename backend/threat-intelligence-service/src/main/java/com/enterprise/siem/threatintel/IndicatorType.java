package com.enterprise.siem.threatintel;

import java.util.Locale;
import java.util.regex.Pattern;

/** Indicator kinds and the canonical (lower-case) form values are stored and matched in. */
public enum IndicatorType {
    IP(null),
    DOMAIN(Pattern.compile("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$")),
    MD5(Pattern.compile("^[a-f0-9]{32}$")),
    SHA1(Pattern.compile("^[a-f0-9]{40}$")),
    SHA256(Pattern.compile("^[a-f0-9]{64}$"));

    private final Pattern format;

    IndicatorType(Pattern format) {
        this.format = format;
    }

    /** @return the canonical value, or throws IllegalArgumentException if it isn't valid for this type. */
    public String canonical(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("value is required");
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        boolean valid = this == IP
                ? com.enterprise.siem.common.validation.IpAddress.Validator.isIp(value)
                : format.matcher(value).matches();
        if (!valid) {
            throw new IllegalArgumentException("not a valid " + name() + " value");
        }
        return value;
    }
}
