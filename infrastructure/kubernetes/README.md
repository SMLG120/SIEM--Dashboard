# Kubernetes Deployment

The Kubernetes assets live in two places:

- `infrastructure/kubernetes/namespace.yaml` — the `siem` namespace used by every workload.
- `infrastructure/helm/siem/` — the primary Helm chart for the whole platform (services, aggregator, and the backing infrastructure: PostgreSQL, Redis, Kafka, Keycloak).

## Quick start

```bash
# 1. Build and publish the images once, then reference them in values.yaml
docker build --platform linux/amd64 \
  -f infrastructure/docker/spring-service.Dockerfile --build-arg SERVICE_PATH=backend/api-gateway \
  -t siem-api-gateway:latest .

kubectl apply -f infrastructure/kubernetes/namespace.yaml

helm install siem infrastructure/helm/siem \
  --namespace siem \
  --set image.repository=siem \
  --set image.tag=latest
```

## Configuration surface

All service settings are centralized in `values.yaml`:

| Value | Meaning |
|-------|---------|
| `image.repository` / `image.tag` | Image prefix/tag used for every image `<repository>-<service>:<tag>` |
| `services.<name>.port` | Container + service port (matches `SERVER_PORT`) |
| `services.<name>.env` | Environment overrides (Kafka, Postgres, Keycloak, OpenSearch…) |
| `dependencies.enabled` | Deploy PostgreSQL, Redis, Kafka and Keycloak in-cluster (`true` by default) |
| `frontend.enabled` | Deploy the dashboard container on port `5173` |

## Notes

- The Keycloak deployment expects the realm bundle in a `ConfigMap` called `siem-keycloak-realm` mounted at `/opt/keycloak/data/import` (the local compose stack generates the same JSON from `infrastructure/keycloak/enterprise-siem-realm.json.template` under `SIEM_REALM_SECRET`):

```bash
kubectl -n siem create configmap siem-keycloak-realm \
  --from-file=enterprise-siem-realm.json=<generated realm JSON>
```

- The gateway routes to downstream services by DNS name, so service names in `values.yaml` must stay aligned with the compose stack (`auth-service`, `ingestion-service`, …).
- Secrets (Postgres password, Keycloak admin password) default to the same values as `.env.example` for local parity; override them for real environments.