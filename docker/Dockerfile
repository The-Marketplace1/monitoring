FROM python:3.12-slim

WORKDIR /monitoring

RUN python -m pip install --no-cache-dir ruff==0.14.10

COPY .dockerignore .env.example .gitignore LICENSE README.md ./
COPY .github ./.github
COPY alerts ./alerts
COPY dashboards ./dashboards
COPY docker ./docker
COPY docs ./docs
COPY health-checks ./health-checks
COPY incidents ./incidents
COPY integrations ./integrations
COPY logging ./logging
COPY metrics ./metrics
COPY rules ./rules
COPY scripts/monitoring.py scripts/validate_repository.py ./scripts/
COPY slo ./slo
COPY synthetic ./synthetic
COPY tests ./tests
COPY tracing ./tracing

CMD ["python", "scripts/monitoring.py", "validate", "."]

