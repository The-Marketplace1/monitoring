import json
import shutil
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

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
        self.assertEqual(event["attributes"]["http.correlation_id"], "corr-123")

    def test_runbook_modification_requires_escalation_sections(self) -> None:
        with copied_repository() as root:
            path = root / "incidents/runbooks/payment-provider.md"
            
            # Formatted to stay under the 88 character maximum line-length limit
            updated_text = path.read_text(encoding="utf-8").replace(
                "## Escalation", "## Contacts"
            )
            path.write_text(updated_text, encoding="utf-8")
            
            with self.assertRaisesRegex(ValueError, "lacks operational sections"):
                validate_repository(root)
