import json
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from scripts.monitoring import (
    CATALOGS,
    REDACTED,
    aggregate_health,
    calculate_ratio_slo,
    load_metric_definitions,
    load_catalogs,
    normalize_event,
    validate_repository,
    validate_source_style,
)


ROOT = Path(__file__).resolve().parents[1]
COPY_DIRECTORIES = (
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
    "scripts",
    "tests",
    "docs",
    "docker",
)
COPY_FILES = (".env.example", ".dockerignore", ".gitignore", "README.md", "LICENSE")


@contextmanager
def copied_repository() -> Iterator[Path]:
    """Create an isolated monitoring tree for destructive validation tests."""
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory)
        for relative in COPY_DIRECTORIES:
            shutil.copytree(ROOT / relative, destination / relative)
        for relative in COPY_FILES:
            shutil.copy2(ROOT / relative, destination / relative)
        shutil.copytree(ROOT / ".github/workflows", destination / ".github/workflows")
        yield destination


def rewrite_json(root: Path, relative_path: str, update: object) -> None:
    path = root / relative_path
    value = json.loads(path.read_text(encoding="utf-8"))
    update(value)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class MonitoringContractsTest(unittest.TestCase):
    def test_repository_contracts_are_valid(self) -> None:
        summary = validate_repository(ROOT)
        self.assertEqual(summary["status"], "valid")
        self.assertEqual(summary["catalogs"], len(CATALOGS))
        self.assertGreaterEqual(summary["source_files"], 3)
        self.assertGreater(summary["metric_definitions"], 50)
        self.assertEqual(summary["runbooks"], 13)
        self.assertGreater(summary["monitored_files"], 100)

    def test_python_source_style_is_valid(self) -> None:
        self.assertGreaterEqual(validate_source_style(ROOT), 3)

    def test_all_catalogs_are_valid_json(self) -> None:
        for relative_path in CATALOGS:
            with (ROOT / relative_path).open(encoding="utf-8") as handle:
                self.assertIsInstance(json.load(handle), dict)
        self.assertEqual(len(load_catalogs(ROOT)), len(CATALOGS))

    def test_normalization_redacts_sensitive_values(self) -> None:
        event = normalize_event(
            {
                "signal": "logs",
                "resource": {"service.name": "booking"},
                "attributes": {"route": "service-owner-approved-route"},
                "authorization": "Bearer should-not-escape",
                "body": {"message": "ok"},
            }
        )
        self.assertEqual(event["authorization"], REDACTED)
        self.assertEqual(event["signal"], "logs")
        self.assertEqual(event["severity_text"], "INFO")
        self.assertEqual(event["body"]["message"], REDACTED)

    def test_normalization_redacts_private_and_precise_location_data(self) -> None:
        event = normalize_event(
            {
                "attributes": {
                    "private_message": "private conversation",
                    "latitude": 6.52,
                    "longitude": 3.37,
                    "email": "person@example.test",
                    "customer_id": "customer-123",
                    "pan": "4111111111111111",
                    "message": "private message body",
                    "error_code": "UPSTREAM_TIMEOUT",
                }
            }
        )
        for key in (
            "private_message",
            "latitude",
            "longitude",
            "email",
            "customer_id",
            "pan",
            "message",
        ):
            self.assertEqual(event["attributes"][key], REDACTED)
        self.assertEqual(event["attributes"]["error_code"], "UPSTREAM_TIMEOUT")

    def test_normalization_maps_marketplace_correlation_fields(self) -> None:
        event = normalize_event(
            {
                "service": "api-gateway",
                "environment": "staging",
                "level": "ERROR",
                "request_id": "req-123",
                "correlation_id": "corr-123",
                "trace_id": "trace-123",
                "operation": "GET service-owner-approved-route",
                "status": 503,
                "duration": 42,
                "error_code": "UPSTREAM_TIMEOUT",
            }
        )
        self.assertEqual(event["resource"]["service.name"], "api-gateway")
        self.assertEqual(event["resource"]["deployment.environment.name"], "staging")
        self.assertEqual(event["severity_text"], "ERROR")
        self.assertEqual(event["attributes"]["http.request.id"], "req-123")
        self.assertEqual(event["attributes"]["marketplace.correlation_id"], "corr-123")
        self.assertEqual(event["attributes"]["trace_id"], "trace-123")

    def test_normalization_rejects_unknown_signal(self) -> None:
        with self.assertRaises(ValueError):
            normalize_event({"signal": "events"})

    def test_health_aggregation_distinguishes_all_states(self) -> None:
        self.assertEqual(aggregate_health(["healthy", "healthy"]), "healthy")
        self.assertEqual(aggregate_health(["healthy", "degraded"]), "degraded")
        self.assertEqual(aggregate_health(["degraded", "unknown"]), "unknown")
        self.assertEqual(aggregate_health(["unknown", "unavailable"]), "unavailable")
        self.assertEqual(aggregate_health([]), "unknown")
        with self.assertRaises(ValueError):
            aggregate_health(["broken"])

    def test_slo_calculation_measures_one_service_or_dependency_series(self) -> None:
        result = calculate_ratio_slo(good_events=998, total_events=1000, target=0.995)
        self.assertEqual(result["sli"], 0.998)
        self.assertAlmostEqual(result["error_budget_remaining"], 0.6)
        self.assertIsNone(calculate_ratio_slo(0, 0, 0.99)["sli"])
        with self.assertRaises(ValueError):
            calculate_ratio_slo(11, 10, 0.99)

    def test_dashboards_have_actionable_panels_and_alerts_have_runbooks(self) -> None:
        catalogs = {catalog["scope"]: catalog for catalog in load_catalogs(ROOT)}
        dashboards = catalogs["dashboards"]["entries"]
        self.assertEqual(len(dashboards), 13)
        self.assertTrue(
            all(panel["purpose"] and panel["metric_refs"] for board in dashboards for panel in board["panels"])
        )
        alerts = catalogs["alerts"]["entries"]
        self.assertGreaterEqual(len(alerts), 15)
        self.assertTrue(all((ROOT / alert["runbook"]).is_file() for alert in alerts))
        self.assertTrue(
            all(
                isinstance(alert["threshold"]["value"], (int, float))
                and alert["threshold"]["window"]
                and alert["escalation"]
                for alert in alerts
            )
        )

    def test_metrics_logging_tracing_and_slo_contracts_cover_operations(self) -> None:
        catalogs = {catalog["scope"]: catalog for catalog in load_catalogs(ROOT)}
        metric_domains = {entry["domain"] for entry in catalogs["metrics"]["entries"]}
        self.assertEqual(
            metric_domains,
            {
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
            },
        )
        self.assertEqual(
            {entry["domain"] for entry in catalogs["logging"]["entries"]},
            {"collection", "parsing", "normalization", "retention", "redaction", "routing"},
        )
        tracing = catalogs["tracing"]
        self.assertIn("API Gateway", tracing["service_to_service"]["boundary"])
        self.assertIn("trace_id", tracing["correlation_fields"])
        slo_domains = {entry["domain"] for entry in catalogs["slo"]["entries"]}
        self.assertEqual(slo_domains, {"availability", "latency", "error-budget", "service-objectives"})

    def test_synthetic_checks_are_safe_and_integrations_are_read_only(self) -> None:
        catalogs = {catalog["scope"]: catalog for catalog in load_catalogs(ROOT)}
        for check in catalogs["synthetic"]["entries"]:
            self.assertFalse(check["mutates_production"])
            self.assertTrue(check["test_identity"])
            self.assertNotEqual(check.get("path"), "/health")
        self.assertFalse(catalogs["health-checks"]["application_health_endpoint"])
        policy = catalogs["integrations"]["integration_policy"]
        self.assertIn("read-only", policy["access"])
        self.assertEqual(policy["transport"], "TLS required in transit")

    def test_metric_definitions_have_units_attributes_and_collection_rules(self) -> None:
        definitions = load_metric_definitions(ROOT)
        self.assertGreater(len(definitions), 50)
        self.assertTrue(
            all(
                definition["unit"] and definition["attributes"] and definition["collection"]
                for definition in definitions.values()
            )
        )

    def test_empty_required_documentation_fails_validation(self) -> None:
        with copied_repository() as root:
            (root / "docs/architecture.md").write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty monitoring-owned files"):
                validate_repository(root)

    def test_catalog_placeholder_fails_validation(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "dashboards/catalog.json",
                lambda catalog: catalog["entries"][0]["panels"][0].update({"purpose": "TODO implement"}),
            )
            with self.assertRaisesRegex(ValueError, "placeholder content"):
                validate_repository(root)

    def test_malformed_metric_configuration_fails_validation(self) -> None:
        with copied_repository() as root:
            (root / "metrics/definitions.json").write_text("{\n", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                validate_repository(root)

    def test_dashboard_rejects_dangling_metric_references(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "dashboards/catalog.json",
                lambda catalog: catalog["entries"][0]["panels"][0].update(
                    {"metric_refs": ["marketplace.metric.does_not_exist"]}
                ),
            )
            with self.assertRaisesRegex(ValueError, "unknown contracts"):
                validate_repository(root)

    def test_alert_requires_numeric_threshold_and_actionable_metadata(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "alerts/catalog.json",
                lambda catalog: catalog["entries"][0]["threshold"].update({"value": "critical"}),
            )
            with self.assertRaisesRegex(ValueError, "invalid actionable alert"):
                validate_repository(root)

    def test_metric_without_unit_fails_configuration_validation(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "metrics/definitions.json",
                lambda catalog: catalog["definitions"][0].update({"unit": ""}),
            )
            with self.assertRaisesRegex(ValueError, "metric definition is incomplete"):
                validate_repository(root)

    def test_metric_rejects_sensitive_attribute_names(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "metrics/definitions.json",
                lambda catalog: catalog["definitions"][0].update({"attributes": ["customer_id"]}),
            )
            with self.assertRaisesRegex(ValueError, "sensitive metric label"):
                validate_repository(root)

    def test_dashboard_rejects_sensitive_grouping_dimensions(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "dashboards/catalog.json",
                lambda catalog: catalog["entries"][0]["panels"][0].update({"group_by": ["customer_id"]}),
            )
            with self.assertRaisesRegex(ValueError, "sensitive data"):
                validate_repository(root)

    def test_slo_rejects_undefined_calculation_inputs(self) -> None:
        with copied_repository() as root:
            rewrite_json(
                root,
                "slo/catalog.json",
                lambda catalog: catalog["entries"][0].update({"metric_refs": ["missing.request.counter"]}),
            )
            with self.assertRaisesRegex(ValueError, "not calculable"):
                validate_repository(root)

    def test_runbook_requires_actionable_sections(self) -> None:
        with copied_repository() as root:
            path = root / "incidents/runbooks/payment-provider.md"
            path.write_text(path.read_text(encoding="utf-8").replace("## Escalation", "## Contacts"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "lacks operational sections"):
                validate_repository(root)


if __name__ == "__main__":
    unittest.main()

