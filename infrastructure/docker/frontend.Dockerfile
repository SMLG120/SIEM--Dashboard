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

FROM nginxinc/nginx-unprivileged:1.27-alpine

COPY infrastructure/docker/frontend-nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
