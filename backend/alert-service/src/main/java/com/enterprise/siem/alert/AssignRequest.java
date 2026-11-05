package com.enterprise.siem.alert;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AssignRequest(
        @NotBlank(message = "assignedTo is required")
        @Size(max = 128)
        String assignedTo
) {
}
