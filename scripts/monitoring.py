"""Portable telemetry helpers and catalog validation for Marketplace Monitoring."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

FORMAT = "marketplace.monitoring.v1"
METRIC_FORMAT = "marketplace.metric-definitions.v1"
CATALOGS = (
    "dashboards/catalog.json",
    "alerts/catalog.json",
    "rules/catalog.json",
    "logging/catalog.json",
    "tracing/catalog.json",
    "metrics/catalog.json",
    "slo/catalog.json",
    "incidents/catalog.json",
    "synthetic/catalog.json",
    "health-checks/catalog.json",
    "integrations/catalog.json",
)
SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|authorization|cookie|api[_-]?key|"
    r"private[_-]?key|connection[_-]?string|card[_-]?number|payment[_-]?(?:credential|card)|"
    r"bank[_-]?account|cvv|cvc|(?:^|[._-])pan(?:$|[._-])|email|phone|"
    r"customer[_-]?(?:id|name|email|phone|address)|professional[_-]?(?:id|name|email|phone|address)|"
    r"user[_-]?(?:id|name|email|phone|address)|first[_-]?name|last[_-]?name|date[_-]?of[_-]?birth|"
    r"private[_-]?message|message(?:[_-]?(?:body|content|text))?|latitude|longitude|coordinates|"
    r"geohash|(?:^|[._-])(?:lat|lng|lon)(?:$|[._-])|precise[_-]?location|location[_-]?coordinates)",
    re.IGNORECASE,
)
REDACTED = "[REDACTED]"
HEALTH_STATES = frozenset({"healthy", "degraded", "unavailable", "unknown"})
ALLOWED_SIGNALS = frozenset({"logs", "metrics", "traces"})
REQUIRED_DIRECTORIES = """
dashboards/platform
dashboards/api-gateway
dashboards/auth
dashboards/backend
dashboards/payments
dashboards/notifications
dashboards/realtime
dashboards/communication
dashboards/location
dashboards/database
dashboards/redis
dashboards/infrastructure
dashboards/security
alerts/platform
alerts/api-gateway
alerts/auth
alerts/backend
alerts/payments
alerts/notifications
alerts/realtime
alerts/communication
alerts/location
alerts/database
alerts/redis
alerts/infrastructure
alerts/security
rules/availability
rules/latency
rules/errors
rules/capacity
rules/security
rules/location
rules/financial
logging/collection
logging/parsing
logging/normalization
logging/retention
logging/redaction
logging/routing
tracing/configuration
tracing/sampling
tracing/propagation
tracing/correlation
metrics/application
metrics/infrastructure
metrics/database
metrics/realtime
metrics/location
metrics/payments
metrics/notifications
metrics/security
slo/availability
slo/latency
slo/error-budget
slo/service-objectives
incidents/runbooks
incidents/escalation
incidents/severity
incidents/response
incidents/postmortems
synthetic/api
synthetic/authentication
synthetic/booking
synthetic/payment
synthetic/realtime
synthetic/location
synthetic/notifications
health-checks/services
health-checks/dependencies
health-checks/databases
health-checks/infrastructure
integrations/aws
integrations/redis
integrations/postgresql
integrations/realtime
integrations/alerting
scripts
tests/alerts
tests/dashboards
tests/metrics
tests/logging
tests/tracing
tests/synthetic
docs
docker
.github/workflows
""".split()
REQUIRED_DASHBOARDS = {
    "platform",
    "api-gateway",
    "auth",
    "backend",
    "payments",
    "notifications",
    "realtime",
    "communication",
    "location",
    "database",
    "redis",
    "infrastructure",
    "security",
}
REQUIRED_METRIC_DOMAINS = {
    "application",
    "infrastructure",
    "database",
    "realtime",
    "location",
    "payments",
    "notifications",
    "security",
    "communication",
    "redis",
}
REQUIRED_ALERT_FIELDS = {"severity", "condition", "threshold", "for", "owner", "escalation", "runbook"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
PLACEHOLDER_TEXT = re.compile(
    r"\b(?:TODO|FIXME|TBD|TBC|CHANGEME|PLACEHOLDER|IMPLEMENT ME|example\.invalid|lorem ipsum)\b|<[^>]+>",
    re.IGNORECASE,
)
ALLOWED_AGGREGATIONS = {"count", "rate", "ratio", "p50", "p95", "p99", "latest", "error-budget"}
ALLOWED_METRIC_TYPES = {"counter", "gauge", "histogram"}


def redact(value: Any, key: str | None = None) -> Any:
    """Return a JSON-compatible value with sensitive fields removed."""
    if key and SENSITIVE_KEY.search(key):
        return REDACTED
    # Unstructured log text cannot be safely inspected for private content.
    if key and key.lower() in {"body", "message"} and isinstance(value, str):
        return REDACTED
    if isinstance(value, dict):
        return {str(item_key): redact(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize an incoming event to a bounded, OTel-compatible event shape."""
    if not isinstance(event, dict):
        raise TypeError("telemetry event must be an object")
    normalized = redact(event)
    resource = normalized.get("resource", {})
    attributes = normalized.get("attributes", {})
    if not isinstance(resource, dict) or not isinstance(attributes, dict):
        raise ValueError("resource and attributes must be objects")
    field_aliases = {
        "request_id": "http.request.id",
        "correlation_id": "marketplace.correlation_id",
        "trace_id": "trace_id",
        "span_id": "span_id",
        "operation": "operation.name",
        "status": "marketplace.status",
        "duration": "marketplace.duration",
        "error_code": "error.code",
    }
    service = normalized.get("service", resource.get("service.name"))
    environment = normalized.get("environment", resource.get("deployment.environment.name"))
    if service is not None:
        normalized["service"] = service
        resource.setdefault("service.name", service)
    if environment is not None:
        normalized["environment"] = environment
        resource.setdefault("deployment.environment.name", environment)
    level = normalized.get("level", normalized.get("severity_text", "INFO"))
    normalized["level"] = level
    normalized["severity_text"] = level
    for field, attribute in field_aliases.items():
        value = normalized.get(field, attributes.get(attribute))
        if value is not None:
            normalized.setdefault(field, value)
            attributes.setdefault(attribute, value)
    for field in ("request_id", "correlation_id", "operation", "status", "duration", "error_code"):
        normalized.setdefault(field, None)
    normalized["resource"] = resource
    normalized["attributes"] = attributes
    normalized.setdefault("observed_at", None)
    normalized["signal"] = str(normalized.get("signal", "logs")).lower()
    if normalized["signal"] not in ALLOWED_SIGNALS:
        raise ValueError("signal must be logs, metrics, or traces")
    return normalized


def calculate_ratio_slo(good_events: int, total_events: int, target: float) -> dict[str, float | None]:
    """Calculate a ratio SLI and remaining error budget for one isolated series."""
    if total_events < 0 or good_events < 0 or good_events > total_events:
        raise ValueError("event counts must satisfy 0 <= good_events <= total_events")
    if not 0 < target < 1:
        raise ValueError("SLO target must be greater than 0 and less than 1")
    if total_events == 0:
        return {"sli": None, "target": target, "error_budget_remaining": None}
    bad_events = total_events - good_events
    allowed_bad_events = total_events * (1 - target)
    remaining = max(0.0, 1 - bad_events / allowed_bad_events)
    return {
        "sli": good_events / total_events,
        "target": target,
        "error_budget_remaining": remaining,
    }


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(SENSITIVE_KEY.search(str(key)) or _contains_sensitive_key(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _contains_sensitive_label(labels: Any) -> bool:
    return isinstance(labels, list) and any(isinstance(label, str) and SENSITIVE_KEY.search(label) for label in labels)


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return bool(PLACEHOLDER_TEXT.search(value))
    if isinstance(value, dict):
        return any(_contains_placeholder(key) or _contains_placeholder(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    return False


def load_metric_definitions(root: Path) -> dict[str, dict[str, Any]]:
    """Load complete, provider-neutral metric definitions."""
    path = root / "metrics/definitions.json"
    if not path.is_file() or not path.read_text(encoding="utf-8").strip():
        raise FileNotFoundError("required metric definition file missing or empty: metrics/definitions.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("metric definition root must be an object")
    if data.get("format") != METRIC_FORMAT or data.get("deployment_status") != "not_deployed":
        raise ValueError("metric definitions must use the provider-neutral, not-deployed contract")
    definitions = data.get("definitions")
    if not isinstance(definitions, list) or not definitions:
        raise ValueError("metric definitions are required")
    result: dict[str, dict[str, Any]] = {}
    for metric in definitions:
        if not isinstance(metric, dict):
            raise ValueError("metric definition must be an object")
        metric_id = metric.get("id")
        required_strings = ("domain", "type", "unit", "description", "collection")
        if (
            not isinstance(metric_id, str)
            or not metric_id.strip()
            or any(not isinstance(metric.get(key), str) or not metric[key].strip() for key in required_strings)
        ):
            raise ValueError(f"metric definition is incomplete: {metric_id!r}")
        if metric["type"] not in ALLOWED_METRIC_TYPES:
            raise ValueError(f"unsupported metric type: {metric_id}")
        if (
            not isinstance(metric["attributes"], list)
            or not metric["attributes"]
            or not all(isinstance(attribute, str) and attribute.strip() for attribute in metric["attributes"])
        ):
            raise ValueError(f"metric attributes must be named dimensions: {metric_id}")
        if _contains_sensitive_label(metric["attributes"]):
            raise ValueError(f"sensitive metric label: {metric_id}")
        if metric_id in result:
            raise ValueError(f"duplicate metric definition: {metric_id}")
        if _contains_sensitive_key(metric):
            raise ValueError(f"sensitive metric attribute: {metric_id}")
        if _contains_placeholder(metric):
            raise ValueError(f"placeholder in metric definition: {metric_id}")
        result[metric_id] = metric
    return result


def validate_runbooks(root: Path) -> int:
    """Require substantive incident procedures with triggers and verification steps."""
    required_sections = (
        "trigger",
        "diagnostics",
        "response",
        "escalation",
        "recovery and verification",
        "evidence",
    )
    runbooks = sorted((root / "incidents/runbooks").glob("*.md"))
    if len(runbooks) != 13:
        raise ValueError(f"expected 13 operational runbooks, found {len(runbooks)}")
    action = re.compile(
        r"\b(?:inspect|check|compare|capture|escalate|verify|record|route|review|confirm|never|do not)\b",
        re.I,
    )
    runbook_texts: dict[str, str] = {}
    for path in runbooks:
        text = path.read_text(encoding="utf-8")
        if not text.strip() or PLACEHOLDER_TEXT.search(text):
            raise ValueError(f"runbook is empty or contains placeholder text: {path.relative_to(root)}")
        normalized = re.sub(r"[^a-z0-9 ]", " ", text.lower())
        missing = [section for section in required_sections if section not in normalized]
        if missing:
            raise ValueError(f"runbook lacks operational sections {missing}: {path.relative_to(root)}")
        if len(action.findall(text)) < 5:
            raise ValueError(f"runbook lacks actionable instructions: {path.relative_to(root)}")
        runbook_texts[path.relative_to(root).as_posix()] = normalized
    for catalog in load_catalogs(root):
        if catalog["scope"] != "alerts":
            continue
        for alert in catalog["entries"]:
            normalized_id = re.sub(r"[^a-z0-9 ]", " ", alert["id"].lower())
            if normalized_id not in runbook_texts.get(alert.get("runbook", ""), ""):
                raise ValueError(f"runbook does not name its alert trigger: {alert['id']}")
    return len(runbooks)


def aggregate_health(states: list[str]) -> str:
    """Aggregate component states without treating missing telemetry as healthy."""
    if not states:
        return "unknown"
    invalid = set(states) - HEALTH_STATES
    if invalid:
        raise ValueError(f"unsupported health state: {sorted(invalid)}")
    if "unavailable" in states:
        return "unavailable"
    if "unknown" in states:
        return "unknown"
    if "degraded" in states:
        return "degraded"
    return "healthy"


def _validate_semantics(root: Path, catalogs: list[dict[str, Any]]) -> None:
    by_scope = {catalog["scope"]: catalog for catalog in catalogs}
    declared_contracts = (
        "alerts",
        "dashboards",
        "health-checks",
        "incidents",
        "logging",
        "metrics",
        "rules",
        "slo",
        "synthetic",
        "tracing",
    )
    for scope in declared_contracts:
        catalog = by_scope[scope]
        if (
            catalog.get("implementation_status") != "validated_provider_neutral_contract"
            or catalog.get("deployment_status") != "not_deployed"
        ):
            raise ValueError(f"{scope} must disclose validated contract versus deployment status")
    metric_definitions = load_metric_definitions(root)
    metric_ids = set(metric_definitions)
    rules = by_scope["rules"]["entries"]
    rule_ids = {rule["id"] for rule in rules}
    rule_outputs = {rule.get("output") for rule in rules}
    slo_ids = {objective["id"] for objective in by_scope["slo"]["entries"]}
    incident_ids = {entry["id"] for entry in by_scope["incidents"]["entries"]}
    valid_references = metric_ids | rule_ids | rule_outputs | slo_ids | incident_ids

    dashboards = by_scope["dashboards"]["entries"]
    dashboard_domains = {entry["domain"] for entry in dashboards}
    if not REQUIRED_DASHBOARDS.issubset(dashboard_domains):
        raise ValueError(f"dashboard domains missing: {sorted(REQUIRED_DASHBOARDS - dashboard_domains)}")
    for dashboard in dashboards:
        if (
            not dashboard.get("owner")
            or not isinstance(dashboard.get("panels"), list)
            or not dashboard["panels"]
            or dashboard.get("deployment_status", by_scope["dashboards"].get("deployment_status")) != "not_deployed"
        ):
            raise ValueError(f"dashboard lacks owner or panels: {dashboard['id']}")
        for panel in dashboard["panels"]:
            if not isinstance(panel, dict) or not all(
                panel.get(field) for field in ("name", "purpose", "metric_refs", "aggregation", "window", "unit")
            ):
                raise ValueError(f"dashboard panel is not operationally defined: {dashboard['id']}")
            if panel.get("aggregation") not in ALLOWED_AGGREGATIONS:
                raise ValueError(f"unsupported dashboard aggregation: {dashboard['id']}:{panel['name']}")
            if not isinstance(panel.get("metric_refs"), list) or not panel["metric_refs"]:
                raise ValueError(f"dashboard panel lacks metric references: {dashboard['id']}:{panel['name']}")
            if "query" in panel or not isinstance(panel["unit"], str) or not panel["unit"].strip():
                raise ValueError(
                    f"dashboard must use provider-neutral references and a unit: {dashboard['id']}:{panel['name']}"
                )
            if _contains_sensitive_label(panel.get("group_by", [])):
                raise ValueError(f"dashboard groups by sensitive data: {dashboard['id']}:{panel['name']}")
            missing_refs = set(panel["metric_refs"]) - valid_references
            if missing_refs:
                raise ValueError(
                    f"dashboard references unknown contracts {sorted(missing_refs)}: {dashboard['id']}:{panel['name']}"
                )
    if by_scope["dashboards"].get("deployment_status") != "not_deployed":
        raise ValueError("dashboards must be explicitly marked as not deployed")

    alerts = by_scope["alerts"]["entries"]
    alert_domains = {entry["domain"] for entry in alerts}
    if not REQUIRED_DASHBOARDS.issubset(alert_domains):
        raise ValueError(f"alert domains missing: {sorted(REQUIRED_DASHBOARDS - alert_domains)}")
    for alert in alerts:
        missing = REQUIRED_ALERT_FIELDS - alert.keys()
        if missing:
            raise ValueError(f"alert contract incomplete for {alert['id']}: {sorted(missing)}")
        threshold = alert["threshold"]
        if (
            not isinstance(alert["severity"], str)
            or alert["severity"] not in ALLOWED_SEVERITIES
            or not isinstance(threshold, dict)
            or not all(key in threshold for key in ("metric_ref", "operator", "value", "unit", "window"))
            or threshold.get("operator") not in {"<", ">", "=="}
            or isinstance(threshold.get("value"), bool)
            or not isinstance(threshold.get("value"), (int, float))
            or not math.isfinite(threshold.get("value", float("nan")))
            or not threshold.get("unit")
            or not threshold.get("window")
            or not isinstance(alert.get("condition"), str)
            or not isinstance(alert.get("for"), str)
            or not alert["owner"]
            or not alert["escalation"]
            or not isinstance(alert.get("metric_refs"), list)
            or not alert.get("metric_refs")
            or threshold.get("metric_ref") not in alert.get("metric_refs", [])
            or not re.fullmatch(r"\d+(?:s|m|h)", alert.get("for", ""))
        ):
            raise ValueError(f"invalid actionable alert: {alert['id']}")
        missing_refs = set(alert.get("metric_refs", [])) - valid_references
        if missing_refs:
            raise ValueError(f"alert references unknown contracts {sorted(missing_refs)}: {alert['id']}")
        runbook_path = root / alert["runbook"]
        if not runbook_path.is_file() or root.resolve() not in runbook_path.resolve().parents:
            raise ValueError(f"alert runbook missing or outside repository: {alert['id']}")
    if by_scope["alerts"].get("deployment_status") != "not_deployed":
        raise ValueError("alerts must be explicitly marked as not deployed")
    if by_scope["alerts"].get("provider") is not None:
        raise ValueError("alerts must not bind to an unselected monitoring provider")

    logging = by_scope["logging"]
    required_log_fields = {
        "timestamp",
        "service",
        "environment",
        "level",
        "request_id",
        "correlation_id",
        "trace_id",
        "operation",
        "status",
        "duration",
        "error_code",
    }
    if not logging.get("structured") or not required_log_fields.issubset(logging.get("required_common_fields", [])):
        raise ValueError("structured logging contract is incomplete")
    redaction = next(entry for entry in logging["entries"] if entry["domain"] == "redaction")
    if not redaction.get("apply_before_routing") or not redaction.get("fail_closed"):
        raise ValueError("logging redaction must fail closed before routing")
    if "TLS" not in logging.get("secure_transport", "") or not logging.get("access_control"):
        raise ValueError("logging must require secure transport and access control")
    retention = next((entry for entry in logging["entries"] if entry["domain"] == "retention"), None)
    if (
        not retention
        or retention.get("deletion_policy") != "automated deletion at tier expiry; no indefinite archive"
        or not retention.get("tiers")
    ):
        raise ValueError("logging retention must have finite, explicit deletion behavior")
    prohibited_values = logging.get("prohibited_data_classes", [])
    if not isinstance(prohibited_values, list) or not all(isinstance(value, str) for value in prohibited_values):
        raise ValueError("logging prohibited-data classes must be strings")
    prohibited_classes = {value.lower() for value in prohibited_values}
    if not {
        "passwords",
        "authentication tokens",
        "api secrets",
        "card and payment credentials",
        "private messages",
        "unnecessary personal information",
        "unnecessary precise location data",
    }.issubset(prohibited_classes):
        raise ValueError("logging privacy exclusions are incomplete")

    tracing = by_scope["tracing"]
    if tracing.get("request_chain") != ["Marketplace", "Service", "Instance", "Request", "Trace", "Error"]:
        raise ValueError("distributed tracing request chain is incomplete")
    if not tracing.get("service_to_service", {}).get("required"):
        raise ValueError("service-to-service trace propagation is required")
    for trace_config in tracing["entries"]:
        if _contains_sensitive_label(trace_config.get("resource_attributes", [])) or _contains_sensitive_label(
            trace_config.get("span_attributes", [])
        ):
            raise ValueError(f"trace attributes contain sensitive dimensions: {trace_config['id']}")
    sampling = next((entry for entry in tracing["entries"] if entry["domain"] == "sampling"), None)
    if (
        not sampling
        or not isinstance(sampling.get("default_ratio"), (int, float))
        or not 0 <= sampling["default_ratio"] <= 1
        or not isinstance(sampling.get("error_ratio"), (int, float))
        or not 0 <= sampling["error_ratio"] <= 1
        or not isinstance(sampling.get("slow_trace_threshold_ms"), (int, float))
        or sampling["slow_trace_threshold_ms"] <= 0
        or not tracing.get("correlation_fields")
    ):
        raise ValueError("trace sampling and correlation policy is invalid")

    metric_domains = {entry["domain"] for entry in by_scope["metrics"]["entries"]}
    if not REQUIRED_METRIC_DOMAINS.issubset(metric_domains):
        raise ValueError(f"metric domains missing: {sorted(REQUIRED_METRIC_DOMAINS - metric_domains)}")
    for metric in by_scope["metrics"]["entries"]:
        if not metric.get("instruments") or not metric.get("measurements"):
            raise ValueError(f"metric definition lacks instruments or operational measurements: {metric['id']}")
        undefined = set(metric["instruments"]) - metric_ids
        if undefined:
            raise ValueError(f"metric group references undefined instruments {sorted(undefined)}: {metric['id']}")
        if _contains_sensitive_label(metric.get("required_attributes", [])):
            raise ValueError(f"metric group requires sensitive dimensions: {metric['id']}")
    for domain in REQUIRED_METRIC_DOMAINS:
        defined_for_domain = {
            metric_id for metric_id, definition in metric_definitions.items() if definition["domain"] == domain
        }
        catalogued_for_domain = {
            metric_id
            for group in by_scope["metrics"]["entries"]
            if group["domain"] == domain
            for metric_id in group["instruments"]
        }
        if defined_for_domain != catalogued_for_domain:
            raise ValueError(f"metric catalog does not match definitions for domain {domain}")

    rule_domains = {entry["domain"] for entry in rules}
    required_rule_domains = {
        "availability",
        "latency",
        "errors",
        "capacity",
        "security",
        "location",
        "financial",
    }
    if not required_rule_domains.issubset(rule_domains):
        raise ValueError("reusable monitoring rules are missing required domains")
    for rule in rules:
        if not rule.get("input_metrics") or not rule.get("calculation") or not rule.get("output"):
            raise ValueError(f"recording rule lacks operational inputs: {rule['id']}")
        if not isinstance(rule.get("unit"), str) or not rule["unit"].strip() or not rule.get("window"):
            raise ValueError(f"recording rule lacks output unit or window: {rule['id']}")
        undefined = set(rule["input_metrics"]) - metric_ids
        if undefined:
            raise ValueError(f"recording rule references undefined metrics {sorted(undefined)}: {rule['id']}")
    financial_rule = next(entry for entry in rules if entry["domain"] == "financial")
    if "payment processing" not in financial_rule.get("forbidden_scope", []):
        raise ValueError("financial rules must remain operational observation, not payment processing")

    slo_domains = {entry["domain"] for entry in by_scope["slo"]["entries"]}
    if not {"availability", "latency", "error-budget", "service-objectives"}.issubset(slo_domains):
        raise ValueError("availability, latency, service-objective, and error-budget SLOs are required")
    for objective in by_scope["slo"]["entries"]:
        if objective["domain"] in {"availability", "latency"} and not objective.get("window"):
            raise ValueError(f"SLO must have a measurement window: {objective['id']}")
        if objective["domain"] in {"availability", "latency"}:
            undefined = set(objective.get("metric_refs", [])) - metric_ids
            if not objective.get("metric_refs") or undefined or not objective.get("calculation"):
                raise ValueError(f"SLO inputs are not calculable from defined metrics: {objective['id']}")
            target = objective.get("target")
            if (
                isinstance(target, bool)
                or not isinstance(target, (int, float))
                or not math.isfinite(target)
                or not 0 < target <= 1
            ):
                raise ValueError(f"SLO target must be numeric and bounded: {objective['id']}")
    budget_policy = next(entry for entry in by_scope["slo"]["entries"] if entry["domain"] == "error-budget")
    availability_slo = next(entry for entry in by_scope["slo"]["entries"] if entry["domain"] == "availability")
    if (
        not math.isclose(budget_policy.get("budget", -1), 1 - availability_slo["target"], rel_tol=1e-9)
        or not budget_policy.get("remaining_budget_calculation")
        or not budget_policy.get("burn_multipliers")
        or not all(
            isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0
            for value in budget_policy["burn_multipliers"]
        )
    ):
        raise ValueError("error budget must be computable from the availability objective")
    if "dependency_treatment" not in by_scope["slo"]["entries"][0]:
        raise ValueError("service availability must distinguish dependency failures")

    synthetic = by_scope["synthetic"]
    if synthetic.get("global_safety", {}).get("production_mutation") is not False:
        raise ValueError("synthetic checks must prohibit production mutations")
    synthetic_domains = {entry["domain"] for entry in synthetic["entries"]}
    required_synthetic_domains = {
        "api",
        "authentication",
        "booking",
        "payment",
        "realtime",
        "location",
        "notifications",
    }
    if not required_synthetic_domains.issubset(synthetic_domains):
        raise ValueError("required synthetic flows are missing")
    for check in synthetic["entries"]:
        if check.get("mutates_production") is not False or not check.get("test_identity"):
            raise ValueError(f"synthetic check lacks safe identity or mutation guard: {check['id']}")
        if check.get("method") not in {"GET", "HEAD"} and check.get("domain") == "api":
            raise ValueError("synthetic API probes must be read-only")
        if check.get("domain") == "api" and (not check.get("target_ref") or not check.get("target_configuration")):
            raise ValueError("synthetic API probes require an explicit owner-configured target")
    payment_check = next(entry for entry in synthetic["entries"] if entry["domain"] == "payment")
    notification_check = next(entry for entry in synthetic["entries"] if entry["domain"] == "notifications")
    if payment_check.get("no_real_charge") is not True or notification_check.get("no_real_recipient") is not True:
        raise ValueError("payment and notification synthetics must not create real transactions")
    if any(check.get("path") == "/health" for check in synthetic["entries"]):
        raise ValueError("synthetic definitions must not assume an unverified health endpoint")
    if synthetic.get("execution_status") != "not_configured" or synthetic.get("deployment_status") != "not_deployed":
        raise ValueError("synthetic probes must not claim execution or deployment before configuration")

    health = by_scope["health-checks"]
    health_states = health.get("states")
    if (
        not isinstance(health_states, list)
        or not all(isinstance(state, str) for state in health_states)
        or set(health_states) != HEALTH_STATES
    ):
        raise ValueError("health checks must distinguish healthy, degraded, unavailable, and unknown")
    if health.get("application_health_endpoint") is not False or health.get("deployment_status") != "not_deployed":
        raise ValueError("health catalog must not invent a running application endpoint")
    if health.get("state_values") != {"unavailable": 0, "degraded": 1, "healthy": 2, "unknown": -1}:
        raise ValueError("health state numeric mapping is incomplete")
    if not any(entry.get("systems") == ["PostgreSQL", "PostGIS"] for entry in health["entries"]):
        raise ValueError("PostgreSQL/PostGIS health checks are required")
    if not any("Redis" in entry.get("systems", []) for entry in health["entries"]):
        raise ValueError("Redis health checks are required")

    integration_policy = by_scope["integrations"].get("integration_policy", {})
    if not isinstance(integration_policy, dict):
        raise ValueError("monitoring integration policy must be an object")
    if integration_policy.get("transport") != "TLS required in transit":
        raise ValueError("monitoring integrations must require secure transport")
    if "read-only" not in integration_policy.get("access", ""):
        raise ValueError("monitoring integrations must use least-privilege read-only access")
    integration_domains = {entry["domain"] for entry in by_scope["integrations"]["entries"]}
    if not {"aws", "redis", "postgresql", "realtime", "alerting"}.issubset(integration_domains):
        raise ValueError("required monitoring integration domains are missing")
    if by_scope["integrations"].get("platform_status") != "awaiting_platform_selection":
        raise ValueError("integrations must disclose that the monitoring platform is not selected")
    if by_scope["integrations"].get("deployment_status") != "not_connected":
        raise ValueError("integrations must disclose that no platform connection exists")
    for integration in by_scope["integrations"]["entries"]:
        if integration.get("status") != "awaiting_platform_selection" or integration.get("connected") is not False:
            raise ValueError(f"integration must remain pending until a platform is selected: {integration['id']}")

    for directory in REQUIRED_DIRECTORIES:
        if not (root / directory).is_dir():
            raise FileNotFoundError(f"required directory missing: {directory}")


def load_catalogs(root: Path) -> list[dict[str, Any]]:
    """Load and validate all required declarative catalogs."""
    catalogs: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for relative_path in CATALOGS:
        path = root / relative_path
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            raise FileNotFoundError(f"required catalog missing or empty: {relative_path}")
        text = path.read_text(encoding="utf-8")
        if not text.endswith("\n") or any(line.rstrip() != line for line in text.splitlines()):
            raise ValueError(f"catalog formatting error: {relative_path}")
        with path.open(encoding="utf-8") as handle:
            catalog = json.load(handle)
        if not isinstance(catalog, dict):
            raise ValueError(f"catalog root must be an object: {relative_path}")
        if _contains_placeholder(catalog):
            raise ValueError(f"placeholder content in catalog: {relative_path}")
        if catalog.get("version") != 1 or catalog.get("format") != FORMAT:
            raise ValueError(f"invalid catalog header: {relative_path}")
        entries = catalog.get("entries")
        if not isinstance(entries, list) or not entries:
            raise ValueError(f"catalog has no entries: {relative_path}")
        local_ids: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"].strip():
                raise ValueError(f"invalid entry in {relative_path}")
            entry_id = entry["id"]
            if entry_id in local_ids or entry_id in seen_ids:
                raise ValueError(f"duplicate entry id: {entry_id}")
            signals = entry.get("signals")
            if (
                not isinstance(entry.get("domain"), str)
                or not entry["domain"].strip()
                or not isinstance(signals, list)
                or not signals
                or not all(isinstance(signal, str) and signal in ALLOWED_SIGNALS for signal in signals)
            ):
                raise ValueError(f"entry contract incomplete: {relative_path}:{entry_id}")
            if _contains_sensitive_key(entry):
                raise ValueError(f"sensitive key in catalog: {relative_path}:{entry_id}")
            local_ids.add(entry_id)
            seen_ids.add(entry_id)
        catalog["path"] = relative_path
        catalogs.append(catalog)
    return catalogs


def validate_source_style(root: Path) -> int:
    """Enforce repository-local Python and JSON formatting without runtime tools."""
    checked = 0
    source_paths = [
        root / "scripts/monitoring.py",
        root / "scripts/validate_repository.py",
        *sorted((root / "tests").rglob("*.py")),
    ]
    for path in source_paths:
        text = path.read_text(encoding="utf-8")
        if not text.endswith("\n"):
            raise ValueError(f"source file must end with a newline: {path.relative_to(root)}")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.endswith((" ", "\t")) or "\t" in line:
                raise ValueError(f"whitespace formatting error: {path.relative_to(root)}:{line_number}")
            if len(line) > 120:
                raise ValueError(f"line exceeds 120 characters: {path.relative_to(root)}:{line_number}")
        checked += 1
    return checked


def validate_no_empty_files(root: Path) -> int:
    """Reject empty files in monitoring-owned source, contract, and documentation trees."""
    owned_directories = (
        "alerts",
        "dashboards",
        "rules",
        "logging",
        "tracing",
        "metrics",
        "slo",
        "incidents",
        "synthetic",
        "health-checks",
        "integrations",
        "tests",
        "docs",
        "docker",
        ".github/workflows",
    )
    empty_files = [
        path.relative_to(root).as_posix()
        for relative in owned_directories
        for path in (root / relative).rglob("*")
        if path.is_file() and path.stat().st_size == 0
    ]
    owned_scripts = (root / "scripts/monitoring.py", root / "scripts/validate_repository.py")
    empty_files.extend(
        path.relative_to(root).as_posix() for path in owned_scripts if path.is_file() and path.stat().st_size == 0
    )
    missing_scripts = [path.relative_to(root).as_posix() for path in owned_scripts if not path.is_file()]
    if missing_scripts:
        raise FileNotFoundError(f"required monitoring scripts missing: {', '.join(missing_scripts)}")
    if empty_files:
        raise ValueError(f"empty monitoring-owned files: {', '.join(sorted(empty_files))}")
    return sum(
        path.is_file() and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}
        for relative in owned_directories
        for path in (root / relative).rglob("*")
    ) + len(owned_scripts)


def validate_repository(root: Path) -> dict[str, Any]:
    """Validate the repository's required contracts and return a summary."""
    monitored_files = validate_no_empty_files(root)
    catalogs = load_catalogs(root)
    _validate_semantics(root, catalogs)
    source_files = validate_source_style(root)
    required_paths = [
        root / ".env.example",
        root / ".dockerignore",
        root / ".gitignore",
        root / "README.md",
        root / "LICENSE",
        root / ".github/workflows/monitoring-validation.yml",
        root / "metrics/definitions.json",
        root / "scripts/monitoring.py",
        root / "scripts/validate_repository.py",
        root / "tests/test_monitoring.py",
        root / "docker/Dockerfile",
        root / "docs/architecture.md",
        root / "docs/operations.md",
        root / "docs/configuration-and-deployment.md",
    ]
    missing = [str(path.relative_to(root)) for path in required_paths if not path.is_file() or not path.stat().st_size]
    if missing:
        raise FileNotFoundError(f"required repository files missing: {', '.join(missing)}")
    environment_lines = [
        line.strip()
        for line in (root / ".env.example").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", line) for line in environment_lines):
        raise ValueError(".env.example must contain environment variable names only")
    workflow = (root / ".github/workflows/monitoring-validation.yml").read_text(encoding="utf-8")
    required_ci_checks = (
        "ruff check",
        "ruff format --check",
        "python -m compileall",
        "python scripts/validate_repository.py",
        "python -m unittest",
        "docker build",
        "docker run",
        "Potential secret-shaped assignment found",
    )
    if any(check not in workflow for check in required_ci_checks):
        raise ValueError("CI workflow is missing an implementation validation step")
    runbook_count = validate_runbooks(root)
    return {
        "catalogs": len(catalogs),
        "entries": sum(len(catalog["entries"]) for catalog in catalogs),
        "format": FORMAT,
        "metric_definitions": len(load_metric_definitions(root)),
        "monitored_files": monitored_files,
        "runbooks": runbook_count,
        "source_files": source_files,
        "status": "valid",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate",))
    parser.add_argument("root", nargs="?", default=".", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_repository(args.root.resolve())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"validation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
