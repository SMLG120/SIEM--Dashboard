package com.enterprise.siem.alert;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AlertNoteRequest(
        @NotBlank(message = "Note text is required")
        @Size(max = 4000)
        String text
) {
}
