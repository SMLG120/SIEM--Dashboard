package com.enterprise.siem.incident;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AddNoteRequest(
        @NotBlank(message = "Note text is required")
        @Size(max = 4000)
        String text
) {
}
