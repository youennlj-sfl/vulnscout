# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_assessments.py.

Targets uncovered branches reported by the CI coverage run:
  cmd_assessments.py – line 115 (warning echo when errors list is non-empty)
"""

import json
import pytest

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
    """Minimal DB: project → variant."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("AssessProject")
        variant = Variant.create("AssessVariant", project.id)
        Scan.create("scan", variant.id, scan_type="sbom")
        _db.session.commit()

        return {
            "project_name": "AssessProject",
            "variant_name": "AssessVariant",
        }


@pytest.fixture()
def app(tmp_path, monkeypatch):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
    ids = _build_db(application)
    application._test_ids = ids
    yield application


@pytest.fixture()
def ids(app):
    return app._test_ids


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCmdAssessmentsCoverage:
    """flask import-custom-assessments coverage."""

    def test_import_json_with_import_errors_prints_warnings(self, app, ids, tmp_path):
        """import-custom-assessments echoes Warning lines when errors are returned (line 115)."""
        variant_name = ids["variant_name"]
        project_name = ids["project_name"]

        # A statement missing 'status' will trigger an error in _import_statements
        vex_doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.com/vex/test",
            "author": "Test",
            "timestamp": "2026-01-01T00:00:00Z",
            "statements": [
                {
                    "@id": "s1",
                    "vulnerability": {"name": "CVE-TEST-001"},
                    "products": [{"@id": "pkg:generic/testpkg@1.0"}],
                    # 'status' intentionally omitted to trigger an error entry
                }
            ],
        }
        json_file = tmp_path / f"{variant_name}.json"
        json_file.write_text(json.dumps(vex_doc))

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments",
            "--project", project_name,
            "--variant", variant_name,
            str(json_file),
        ])

        assert result.exit_code == 0
        assert "Warning:" in result.output

    def test_import_unsupported_extension_exits(self, app, ids, tmp_path):
        """Unsupported file extension (not .json or .tar.gz) exits with code 1."""
        bad_file = tmp_path / "assessments.csv"
        bad_file.write_text("data")

        runner = app.test_cli_runner()
        result = runner.invoke(args=[
            "import-custom-assessments",
            "--project", ids["project_name"],
            str(bad_file),
        ])

        assert result.exit_code != 0
        assert "unsupported file type" in result.output
