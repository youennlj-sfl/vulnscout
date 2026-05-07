# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Coverage tests for src/bin/cmd_process.py.

Targets uncovered branches reported by the CI coverage run:
  cmd_process.py – lines 131, 152, 236, 255-256, 302-303, 348, 360-361
"""

import json
import pytest
from unittest.mock import patch, MagicMock

from src.bin.webapp import create_app
from src.extensions import db as _db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_db(app):
    """Minimal DB: project → variant → scan."""
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan

    with app.app_context():
        _db.drop_all()
        _db.create_all()

        project = Project.create("ProcessProject")
        variant = Variant.create("ProcessVariant", project.id)
        Scan.create("scan", variant.id, scan_type="sbom")
        _db.session.commit()


@pytest.fixture()
def app(tmp_path, monkeypatch):
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    application = create_app()
    application.config.update({"TESTING": True, "SCAN_FILE": str(scan_file)})
    _build_db(application)
    yield application


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCmdProcessCoverage:
    """flask process and helper-function coverage."""

    def test_process_command_invokes_run_main(self, app):
        """flask process calls _run_main (line 236)."""
        with patch("src.bin.cmd_process._run_main") as mock_main:
            mock_main.return_value = {}
            runner = app.test_cli_runner()
            result = runner.invoke(args=["process"])
        mock_main.assert_called_once()

    def test_populate_observations_no_scan_prints_warning(self, app, capsys):
        """populate_observations(None, …) prints warning and returns early (lines 255-256)."""
        from src.bin.cmd_process import populate_observations
        mock_ctrl = MagicMock()
        mock_ctrl._encountered_this_run = set()

        with app.app_context():
            populate_observations(None, mock_ctrl)
        assert "Warning: no scan provided" in capsys.readouterr().out

    def test_populate_observations_db_exception_is_warned(self, app, capsys):
        """DB error inside populate_observations is caught and printed (lines 302-303)."""
        from src.bin.cmd_process import populate_observations
        mock_ctrl = MagicMock()
        mock_ctrl._encountered_this_run = {"CVE-FAKE"}

        mock_scan = MagicMock()
        mock_scan.id = "fake-scan-id"

        with app.app_context():
            with patch("src.bin.cmd_process._db") as mock_db:
                mock_db.session.execute.side_effect = RuntimeError("db failure")
                mock_db.select = _db.select
                populate_observations(mock_scan, mock_ctrl)

        assert "Warning: could not populate observations table" in capsys.readouterr().out

    def test_run_main_interactive_mode_skips_post_treatment(self, app, monkeypatch):
        """_run_main skips post_treatment when INTERACTIVE_MODE=true (line 348)."""
        monkeypatch.setenv("INTERACTIVE_MODE", "true")
        with patch("src.bin.cmd_process.post_treatment") as mock_pt, \
             patch("src.bin.cmd_process.read_inputs") as mock_ri, \
             patch("src.bin.cmd_process.populate_observations"):
            mock_ri.return_value = {}
            with app.app_context():
                from src.bin.cmd_process import _run_main
                _run_main()
        mock_pt.assert_not_called()

    def test_run_main_json_cache_write_exception_swallowed(self, app, monkeypatch):
        """IO error writing JSON cache is silently swallowed (lines 360-361)."""
        import json as _json_mod

        monkeypatch.setenv("MATCH_CONDITION", "cvss > 5")
        with patch("src.bin.cmd_process.read_inputs") as mock_ri, \
             patch("src.bin.cmd_process.post_treatment"), \
             patch("src.bin.cmd_process.populate_observations"), \
             patch("src.bin.cmd_process.evaluate_condition", return_value=[]), \
             patch.object(_json_mod, "dump", side_effect=OSError("disk full")):
            mock_ri.return_value = {}
            with app.app_context():
                from src.bin.cmd_process import _run_main
                _run_main()  # Must not raise despite json.dump() failing

    def test_read_inputs_unknown_format_prints_warning(self, app, tmp_path, capsys):
        """read_inputs prints a warning for docs with unrecognisable format (line 152)."""
        from src.bin.cmd_process import read_inputs
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.assessments import AssessmentsController
        from src.models.sbom_document import SBOMDocument
        from src.models.scan import Scan

        unknown_file = tmp_path / "unknown.json"
        # Content that doesn't match SPDX, CycloneDX, OpenVEX, Yocto or Grype
        unknown_file.write_text(json.dumps({"totally_unknown": "value", "xyz": 42}))

        with app.app_context():
            scan = _db.session.execute(_db.select(Scan)).scalar_one()
            SBOMDocument.create(str(unknown_file), "unknown.json", scan.id, format=None)
            _db.session.commit()

            pkgCtrl = PackagesController()
            vulnCtrl = VulnerabilitiesController(pkgCtrl)
            assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
            controllers = {
                "packages": pkgCtrl,
                "vulnerabilities": vulnCtrl,
                "assessments": assessCtrl,
            }

            read_inputs(controllers, scan_id=scan.id)

        assert "Warning: unknown format" in capsys.readouterr().out

    def test_read_inputs_spdx3_uses_fast_parser(self, app, tmp_path):
        """read_inputs dispatches to FastSPDX3.parse_from_dict for SPDX 3 docs (line 131)."""
        from src.bin.cmd_process import read_inputs
        from src.controllers.packages import PackagesController
        from src.controllers.vulnerabilities import VulnerabilitiesController
        from src.controllers.assessments import AssessmentsController
        from src.models.sbom_document import SBOMDocument
        from src.models.scan import Scan

        # Minimal SPDX 3 JSON structure that passes could_parse_spdx()
        spdx3_data = {
            "@graph": [
                {"@type": "CreationInfo", "specVersion": "3.0.0"},
            ]
        }
        spdx3_file = tmp_path / "sbom_spdx3.spdx.json"
        spdx3_file.write_text(json.dumps(spdx3_data))

        with app.app_context():
            scan = _db.session.execute(_db.select(Scan)).scalar_one()
            SBOMDocument.create(str(spdx3_file), "sbom_spdx3.spdx.json", scan.id, format="spdx")
            _db.session.commit()

            pkgCtrl = PackagesController()
            vulnCtrl = VulnerabilitiesController(pkgCtrl)
            assessCtrl = AssessmentsController(pkgCtrl, vulnCtrl)
            controllers = {
                "packages": pkgCtrl,
                "vulnerabilities": vulnCtrl,
                "assessments": assessCtrl,
            }

            with patch("src.views.fast_spdx3.FastSPDX3.parse_from_dict") as mock_parse:
                read_inputs(controllers, scan_id=scan.id)

        mock_parse.assert_called_once_with(spdx3_data)
