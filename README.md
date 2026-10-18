# Marketplace Monitoring

Provider-neutral observability contracts and validation for Marketplace. The
repository contains 11 catalogs with 87 validated contract entries, 13
operator runbooks, metric definitions, executable validation/normalization
code, tests, and deployment documentation.

## Status: validated, not deployed

| Layer | Current state |
| --- | --- |
| Executable repository tooling | Implemented: catalog/reference validation, structured-event normalization and redaction, health-state aggregation, and SLO/error-budget calculations |
| Monitoring contracts | Validated and provider-neutral; dashboards, alerts, rules, metrics, log/tracing conventions, SLOs, health checks, synthetic checks, and runbooks are defined |
| Provider integration | Awaiting platform selection; integrations are disconnected and no vendor adapter is configured |
| Telemetry collection and dashboards | Not deployed; no telemetry is claimed to be collected and no dashboard or alert is live |

OpenTelemetry-compatible names and W3C trace conventions form the portable
boundary. Marketplace services emit standard telemetry; a future adapter maps
the contracts to AWS-native monitoring, Grafana, Datadog, New Relic, or another
chosen platform. Do not add provider-specific query syntax or mark a definition
as deployed before it exists in that platform.

## Validate locally

The scripts use Python's standard library. Ruff is used for lint and formatting:

```bash
python scripts/validate_repository.py
python -m unittest discover -s tests -p 'test_*.py'
ruff check scripts tests
ruff format --check --line-length 120 scripts tests
python -m compileall -q scripts tests
```

When Docker is available, validate the image and one-shot startup:

```bash
docker build --file docker/Dockerfile --tag marketplace-monitoring:local .
docker run --rm --network none marketplace-monitoring:local
```

The container runs validation and exits; this repository is not a long-running
application and has no HTTP `/health` endpoint. GitHub Actions also runs
catalog validation, tests, Ruff, compilation, secret/config checks, Docker
validation and the one-shot smoke test. Any failed command fails the job.

## How completeness is checked

The validator checks non-empty required files, placeholders, metric definitions
and units, provider-neutral dashboard references, numeric alert thresholds,
severity/ownership/escalation, live runbook references, runbook action sections,
SLO inputs/calculability, integration status, privacy boundaries, and malformed
JSON. Tests exercise normalization/redaction, health aggregation, SLO math, and
negative cases where incomplete contracts must fail.

## Configure, operate, and deploy

See [architecture](docs/architecture.md), [operations](docs/operations.md), and
[configuration and deployment](docs/configuration-and-deployment.md). The
catalogs describe intended contracts. A configured collector, provider
adapter, and selected monitoring platform are still required before telemetry
collection or dashboards/alerts can be considered active.

Environment variable names are listed in `.env.example`; secret values belong
in the deployment's secret manager and must not be committed.

## Repository boundaries

Monitoring consumes telemetry and read-only health signals through declared
contracts. It does not change service data, implement booking or payment
behavior, authorize transactions, or connect directly to another repository's
private database. Private messages, credentials, payment details, and
unnecessary precise location data are excluded.
