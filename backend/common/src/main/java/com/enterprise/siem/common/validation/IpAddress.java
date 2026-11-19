package com.enterprise.siem.common.validation;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * Accepts a literal IPv4 or IPv6 address (or null). Hostnames are rejected without any DNS lookup.
 */
@Documented
@Constraint(validatedBy = IpAddress.Validator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT, ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
public @interface IpAddress {
    String message() default "must be a literal IPv4 or IPv6 address";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    final class Validator implements ConstraintValidator<IpAddress, String> {
        private static final Pattern IPV4 = Pattern.compile(
                "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
        private static final Pattern IPV6_CHARS = Pattern.compile("^[0-9A-Fa-f:.]{2,45}$");

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            return value == null || isIp(value);
        }

        public static boolean isIp(String value) {
            if (IPV4.matcher(value).matches()) {
                return true;
            }
            if (!value.contains(":") || !IPV6_CHARS.matcher(value).matches()) {
                return false;
            }
            try {
                // Only hex digits, ':' and '.' reach this point, so this parses a literal and never resolves DNS.
                return InetAddress.getByName(value) != null;
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }
}
