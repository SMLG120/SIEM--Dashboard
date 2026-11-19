package com.enterprise.siem.common;

import com.enterprise.siem.common.web.RequestBodyLimitFilter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequestBodyLimitFilterTest {
    private final RequestBodyLimitFilter filter = new RequestBodyLimitFilter(10);

    @Test
    void rejectsDeclaredOversizedBody() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/events");
        request.setContent(new byte[11]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, response, chain);
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    void failsUndeclaredBodyOnceItPassesTheLimit() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/events") {
            @Override
            public long getContentLengthLong() {
                return -1; // chunked
            }
        };
        request.setContent(new byte[64]);
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        InputStream in = chain.getRequest().getInputStream();
        assertThatThrownBy(() -> in.readAllBytes()).isInstanceOf(RequestBodyLimitFilter.BodyTooLargeException.class);
    }

    @Test
    void passesSmallBodies() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/events");
        request.setContent("{\"a\":1}".getBytes());
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest().getInputStream().readAllBytes()).hasSize(7);
    }
}
