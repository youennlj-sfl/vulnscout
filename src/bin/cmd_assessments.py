# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Custom assessment import/export commands:
``flask export-custom-assessments`` and ``flask import-custom-assessments``."""

import io
import click
import json as _json
import tarfile
import uuid as _uuid
import os
from flask.cli import with_appcontext
from ..helpers.assessment_io import (
    build_openvex_archive,
    is_openvex_doc,
    import_statements as _import_openvex_statements,
    build_variant_by_name_map,
    import_archive_bytes,
)
from ..models.assessment import Assessment as DBAssessment
from ..models.variant import Variant as DBVariant
from datetime import datetime as _dt, timezone as _tz
from collections import defaultdict

@click.command("export-custom-assessments")
@click.option("--output-dir", default="/scan/outputs", show_default=True,
              help="Directory where the exported file is written.")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help="Variant name. If empty, all variants will be exported in an archive.")
@with_appcontext
def export_custom_assessments_command(output_dir: str, project: str, variant: str | None) -> None:
    """Export handmade (custom) assessments as an (archive of) OpenVEX file(s)."""

    author = os.getenv("AUTHOR_NAME", "Savoir-faire Linux")
    now_iso = _dt.now(_tz.utc).isoformat()

    project_obj = ProjectController.get_by_name(project)
    if not project_obj:
        click.echo(f"Error: project not found: {project}")
        raise SystemExit(1)

    variants: list[DBVariant]
    if variant:
        variant_obj = DBVariant.get_by_name_and_project(variant, project_obj.id)
        if not variant_obj:
            click.echo(f"Error: variant not found: {variant}")
            raise SystemExit(1)
        variants = [variant_obj]
    else:
        variants = DBVariant.get_by_project(project_obj.id)

    vuln_cache: dict[str, DBVuln | None] = {}

    def _get_vuln(vuln_id: str):
        if vuln_id not in vuln_cache:
            vuln_cache[vuln_id] = DBVuln.get_by_id(vuln_id)
        return vuln_cache[vuln_id]

    handmade = DBAssessment.get_handmade([variant_obj.id for variant_obj in variants])
    if not handmade:
        click.echo("No custom assessments to export.", err=True)
        raise SystemExit(1)

    archive_bytes = build_openvex_archive(handmade, variant_names, author)
    os.makedirs(output_dir, exist_ok=True)

    def generate_doc(assessments: list[DBAssessment]) -> dict:
        statements = []
        for assess in assessments:
            stmt = assess.to_openvex_dict()
            if stmt is None:
                continue

            vuln_obj = (
                _get_vuln(assess.vuln_id)
                if assess.vuln_id else None
            )
            description = ""
            aliases: list[str] = []
            vuln_url = ""
            if vuln_obj:
                desc = vuln_obj.texts.get("description", "")
                yocto_desc = vuln_obj.texts.get(
                    "yocto description", ""
                )
                description = desc or yocto_desc or ""
                aliases = list(vuln_obj.aliases or [])
                urls = (
                    list(vuln_obj.urls) if vuln_obj.urls
                    else list(vuln_obj.links or [])
                )
                vuln_url = urls[0] if urls else ""
                if (
                    not vuln_url
                    and assess.vuln_id.startswith("CVE-")
                ):
                    vuln_url = (
                        "https://nvd.nist.gov/vuln/detail/"
                        + assess.vuln_id
                    )
                elif (
                    not vuln_url
                    and assess.vuln_id.startswith("GHSA-")
                ):
                    vuln_url = (
                        "https://github.com/advisories/"
                        + assess.vuln_id
                    )

            stmt["vulnerability"] = {
                "name": assess.vuln_id,
                "description": description,
                "aliases": aliases,
                "@id": vuln_url,
            }

            products = []
            for pkg_str in assess.packages:
                if "@" in pkg_str:
                    name, version = pkg_str.rsplit("@", 1)
                else:
                    name, version = pkg_str, ""
                products.append({
                    "@id": pkg_str,
                    "identifiers": {
                        "cpe23": (
                            "cpe:2.3:*:*:"
                            f"{name}:{version}"
                            ":*:*:*:*:*:*:*"
                        ),
                        "purl": f"pkg:generic/{name}@{version}",
                    }
                })
            stmt["products"] = products
            stmt.setdefault("action_statement_timestamp", "")
            stmt["scanners"] = list({
                assess.source or "local_user_data",
                assess.origin or "local_user_data",
            })
            statements.append(stmt)

        doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": (
                "https://savoirfairelinux.com/sbom/openvex/"
                + str(_uuid.uuid4())
            ),
            "author": author,
            "timestamp": now_iso,
            "version": 1,
            "statements": statements,
        }
        return doc

    if variant is None:
        # export all variants from project as archive
        by_variant: dict[uuid.UUID, list[DBAssessment]] = defaultdict(list)
        for assess in handmade:
            by_variant[assess.variant_id].append(assess)

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for vid, assessments in by_variant.items():
                variant_obj = DBVariant.get_by_id(vid)
                assert variant_obj  # Variant cannot be null since we filtrered by variant before
                filename = variant_obj.name + ".json"
                filename = filename.replace("/", "_").replace("\\", "_")

                doc = generate_doc(assessments)
                json_bytes = _json.dumps(doc, indent=2).encode("utf-8")
                info = tarfile.TarInfo(name=filename)
                info.size = len(json_bytes)
                tar.addfile(info, io.BytesIO(json_bytes))

        out_path = os.path.join(output_dir, "custom_assessments.tar.gz")
        with open(out_path, "wb") as fh:
            fh.write(buf.getvalue())
    else:
        assert variant_obj
        # Declared above, assert here so type checker no longer
        # considers it possibly Unbound
        filename = variant_obj.name + ".json"
        filename = filename.replace("/", "_").replace("\\", "_")

        doc = generate_doc(handmade)
        out_path = os.path.join(output_dir, filename)
        with open(out_path, "w") as file:
            _json.dump(doc, file)

    click.echo(f"Custom assessments exported: {out_path}")

@click.command("import-custom-assessments")
@click.argument("file_path")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None, help="Variant name. Defaults to the file name.")
@with_appcontext
def import_custom_assessments_command(file_path: str, project: str, variant: str | None) -> None:
    """Import custom assessments from a .json or .tar.gz OpenVEX file."""
    if not os.path.isfile(file_path):
        click.echo(f"Error: file not found: {file_path}", err=True)
        raise SystemExit(1)

    project_obj = ProjectController.get_by_name(project)
    if not project_obj:
        click.echo(f"Error: project not found: {project}")
        raise SystemExit(1)

    if variant:
        variant_obj = DBVariant.get_by_name_and_project(variant, project_obj.id)
        if not variant_obj:
            click.echo(f"Error: variant not found: {variant}")
            raise SystemExit(1)
    else:
        all_variants = DBVariant.get_by_project(project_obj.id)
        variant_by_name: dict[str, "DBVariant"] = {}
        for v in all_variants:
            sanitised = v.name.replace("/", "_").replace("\\", "_")
            variant_by_name[sanitised] = v
            variant_by_name[v.name] = v

    def _is_openvex(doc: dict) -> bool:
        ctx = doc.get("@context", "")
        return "openvex" in ctx and isinstance(
            doc.get("statements"), list
        )

    def _import_statements(
        statements: list, variant_id
    ) -> tuple[list, list, int]:
        created: list[dict] = []
        errors: list[dict] = []
        skipped = 0
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            vuln_obj = stmt.get("vulnerability", {})
            vuln_name = (
                vuln_obj.get("name")
                if isinstance(vuln_obj, dict) else None
            )
            if not vuln_name:
                errors.append({
                    "error": "Missing vulnerability name",
                    "statement": str(stmt)[:200],
                })
                continue
            status = stmt.get("status")
            if not status:
                errors.append({
                    "vuln_id": vuln_name,
                    "error": "Missing status",
                })
                continue

            products = stmt.get("products", [])
            pkg_ids = []
            for prod in products:
                if isinstance(prod, dict) and "@id" in prod:
                    pkg_ids.append(prod["@id"])
                elif isinstance(prod, str):
                    pkg_ids.append(prod)
            if not pkg_ids:
                errors.append({
                    "vuln_id": vuln_name,
                    "error": "No products/packages found",
                })
                continue

            justification = stmt.get("justification", "")
            impact_statement = stmt.get("impact_statement", "")
            status_notes = stmt.get("status_notes", "")
            workaround = stmt.get("action_statement", "")

            for pkg_string_id in pkg_ids:
                try:
                    if "@" in pkg_string_id:
                        name, version = pkg_string_id.rsplit(
                            "@", 1
                        )
                    else:
                        name, version = pkg_string_id, ""
                    db_pkg = Package.find_or_create(name, version)
                    DBVuln.get_or_create(vuln_name)
                    finding = Finding.get_or_create(
                        db_pkg.id, vuln_name
                    )

                    existing = _db.session.execute(
                        _db.select(DBAssessment).where(
                            DBAssessment.finding_id == finding.id,
                            DBAssessment.variant_id == variant_id,
                            DBAssessment.status == status,
                        )
                    ).scalar_one_or_none()
                    if existing is not None:
                        skipped += 1
                        continue

                    db_a = DBAssessment.create(
                        status=status,
                        simplified_status=(
                            STATUS_TO_SIMPLIFIED.get(
                                status, "Pending Assessment"
                            )
                        ),
                        finding_id=finding.id,
                        variant_id=variant_id,
                        origin="custom",
                        status_notes=status_notes,
                        justification=justification,
                        impact_statement=impact_statement,
                        workaround=workaround,
                        responses=[],
                        commit=True,
                    )
                    created.append(db_a.to_dict())
                except Exception as e:
                    errors.append({
                        "vuln_id": vuln_name,
                        "package": pkg_string_id,
                        "error": str(e),
                    })
        return created, errors, skipped

    variant_by_name = build_variant_by_name_map()
    basename = os.path.basename(file_path)
    total_created: list[dict] = []
    total_errors: list[dict] = []
    total_skipped = 0

    if file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
        if variant:
            click.echo("Error: cannot use the --variant argument with an archive of custom assessments.")
            raise SystemExit(1)

        try:
            with open(file_path, "rb") as fh:
                archive_bytes = fh.read()
            total_created, total_errors, total_skipped, found = import_archive_bytes(
                archive_bytes, variant_by_name
            )
        except ValueError:
            click.echo("Error: unable to open tar.gz archive.", err=True)
            raise SystemExit(1)

        variant_files_found = 0
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(
                ".json"
            ):
                continue
            base = os.path.basename(member.name)
            variant_name = base[:-len(".json")]
            variant_obj = variant_by_name.get(variant_name)
            if variant_obj is None:
                total_errors.append({
                    "file": member.name,
                    "error": (
                        f"No variant found matching name "
                        f"'{variant_name}'"
                    ),
                })
                continue

            f = tar.extractfile(member)
            if f is None:
                continue
            try:
                doc = _json.load(f)
            except Exception:
                total_errors.append({
                    "file": member.name,
                    "error": "Invalid JSON",
                })
                continue

            if not _is_openvex(doc):
                total_errors.append({
                    "file": member.name,
                    "error": "Not a valid OpenVEX document",
                })
                continue

            variant_files_found += 1
            c, e, s = _import_statements(
                doc["statements"], variant_obj.id
            )
            total_created.extend(c)
            total_errors.extend(e)
            total_skipped += s

        tar.close()

        if variant_files_found == 0 and not total_created:
            click.echo(
                "Error: no valid OpenVEX files matching known "
                "variants found in archive.", err=True
            )
            for err in total_errors:
                click.echo(f"  {err}", err=True)
            raise SystemExit(1)

    elif file_path.endswith(".json"):
        if variant:
            assert variant_obj
            # Declared above, assert here so type checker no longer
            # considers it possibly Unbound
        else:
            variant_name = variant if variant else basename[:-len(".json")]
            variant_obj = variant_by_name.get(variant_name)
            if variant_obj is None:
                click.echo(
                    f"Error: no variant found matching filename "
                    f"'{variant_name}'. The JSON filename must "
                    f"correspond to an existing variant name. "
                    "Hint: use --variant to specify another name.",
                    err=True,
                )
                raise SystemExit(1)

        try:
            with open(file_path) as fh:
                data = json.load(fh)
        except Exception:
            click.echo("Error: invalid JSON file.", err=True)
            raise SystemExit(1)

        if not is_openvex_doc(data):
            click.echo("Error: not a valid OpenVEX document.", err=True)
            raise SystemExit(1)

        c, e, s = _import_statements(
            data["statements"], variant_obj.id
        )
    else:
        click.echo(
            "Error: unsupported file type. "
            "Please provide a .json or .tar.gz file.",
            err=True,
        )
        raise SystemExit(1)

    for err in total_errors:
        click.echo(f"  Warning: {err}", err=True)

    click.echo(
        f"Imported {len(total_created)} assessments"
        f" ({total_skipped} skipped as duplicates)"
    )
