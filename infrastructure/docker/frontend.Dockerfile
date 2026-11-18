FROM node:24-alpine AS build

WORKDIR /app
COPY frontend/siem-dashboard/package*.json ./
RUN npm ci
COPY frontend/siem-dashboard .
ARG VITE_API_BASE_URL
ARG VITE_KEYCLOAK_URL
ARG VITE_KEYCLOAK_REALM
ARG VITE_KEYCLOAK_CLIENT_ID
RUN npm run build

# Build the CSP connect-src from the origins the console calls: the API gateway and Keycloak.
COPY infrastructure/docker/frontend-nginx.conf /tmp/nginx.conf
RUN set -eu; \
    connect="'self'"; \
    for url in "$VITE_API_BASE_URL" "$VITE_KEYCLOAK_URL"; do \
      [ -n "$url" ] || continue; \
      origin="$(printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*#\1#')"; \
      printf '%s' "$origin" | grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]+)?$' \
        || { echo "invalid origin for CSP: $url" >&2; exit 1; }; \
      case " $connect " in *" $origin "*) ;; *) connect="$connect $origin" ;; esac; \
    done; \
    sed "s#__CSP_CONNECT_SRC__#$connect#" /tmp/nginx.conf > /app/nginx.conf; \
    ! grep -q '__CSP_CONNECT_SRC__' /app/nginx.conf

FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY --from=build /app/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
# nginx-unprivileged already runs as uid 101; stated explicitly so it is verifiable.
USER 101
EXPOSE 8080
