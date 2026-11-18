package com.enterprise.siem.alert;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record AssignRequest(
        @NotBlank(message = "assignedTo is required")
        @Size(max = 128)
        @Pattern(regexp = "^[A-Za-z0-9._@-]+$", message = "assignedTo must be a username")
        String assignedTo
) {
}
