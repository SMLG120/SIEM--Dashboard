# Deployment

Phase 1 local deployment is Docker Compose based:

```bash
cp .env.example .env
docker compose up --build
```

Before running, replace the placeholder values in `.env`, especially:

- `KEYCLOAK_ADMIN_PASSWORD`
- `SIEM_DEMO_PASSWORD`
- `POSTGRES_PASSWORD`

The repository ships test-friendly defaults (`admin` / `admin123` for Keycloak and the realm demo users) so the stack boots and the demo script works without edits. Change them for any shared environment.

Kubernetes and Helm assets are reserved for Phase 11 after the service APIs and runtime contracts are stable.
