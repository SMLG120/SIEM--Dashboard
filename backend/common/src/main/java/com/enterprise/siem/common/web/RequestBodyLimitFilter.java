package com.enterprise.siem.common.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Caps request bodies at {@code maxBytes}. Declared lengths over the cap get 413 at once; bodies
 * without a length (chunked) are counted as they are read and fail once they pass the cap, so a
 * client can't stream an unbounded body into a JSON parser.
 */
public class RequestBodyLimitFilter extends OncePerRequestFilter {
    private final long maxBytes;

    public RequestBodyLimitFilter(long maxBytes) {
        this.maxBytes = maxBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long declared = request.getContentLengthLong();
        if (declared > maxBytes) {
            response.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, "Request body too large");
            return;
        }
        chain.doFilter(new LimitedRequest(request, maxBytes), response);
    }

    /** Thrown while reading; Spring turns an unreadable body into 400, which also ends the request. */
    public static final class BodyTooLargeException extends IOException {
        BodyTooLargeException(long max) {
            super("Request body exceeds " + max + " bytes");
        }
    }

    private static final class LimitedRequest extends HttpServletRequestWrapper {
        private final long max;
        private ServletInputStream stream;

        LimitedRequest(HttpServletRequest request, long max) {
            super(request);
            this.max = max;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                ServletInputStream delegate = super.getInputStream();
                stream = new ServletInputStream() {
                    private long count;

                    private int track(int n) throws IOException {
                        if (n > 0) {
                            count += n;
                            if (count > max) {
                                throw new BodyTooLargeException(max);
                            }
                        }
                        return n;
                    }

                    @Override
                    public int read() throws IOException {
                        int b = delegate.read();
                        if (b >= 0) {
                            track(1);
                        }
                        return b;
                    }

                    @Override
                    public int read(byte[] buf, int off, int len) throws IOException {
                        return track(delegate.read(buf, off, len));
                    }

                    @Override
                    public boolean isFinished() {
                        return delegate.isFinished();
                    }

                    @Override
                    public boolean isReady() {
                        return delegate.isReady();
                    }

                    @Override
                    public void setReadListener(ReadListener listener) {
                        delegate.setReadListener(listener);
                    }
                };
            }
            return stream;
        }
    }
}
