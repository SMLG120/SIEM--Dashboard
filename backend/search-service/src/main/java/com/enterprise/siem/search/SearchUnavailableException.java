package com.enterprise.siem.search;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/** The search backend failed; callers get 503 rather than a misleading empty result. */
@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
public class SearchUnavailableException extends RuntimeException {
    public SearchUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
