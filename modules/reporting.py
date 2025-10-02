# modules/reporting.py
import os
import re
import io
import json
import zipfile
import hashlib
import tempfile
import datetime
from typing import List, Dict, Optional

from flask import Blueprint, current_app, render_template, request, send_file, abort, url_for

# Only allow simple case ids (no path traversal)
CASE_ID_RE = re.compile(r'^[A-Za-z0-9_\-]+$')

def _safe_case_id(case_id: str) -> Optional[str]:
    if not case_id:
        return None
    if CASE_ID_RE.match(case_id):
        return case_id
    return None

def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def _collect_case_files(case_id: str) -> Dict:
    """
    Collect candidate files for report for the given case.
    Returns dict with keys: data_dir, evidence_dir, processes, events, artifacts_meta (list of dicts)
    """
    base = {}
    data_dir = os.path.join("data", case_id)
    evidence_artifacts_dir = os.path.join("evidence", case_id, "artifacts")
    base["data_dir"] = data_dir
    base["evidence_artifacts_dir"] = evidence_artifacts_dir
    processes = os.path.join(data_dir, "processes.csv")
    events = os.path.join(data_dir, "events.json")
    base["processes_path"] = processes
    base["events_path"] = events

    artifacts = []
    if os.path.isdir(evidence_artifacts_dir):
        for entry in sorted(os.listdir(evidence_artifacts_dir)):
            if not entry.lower().endswith(".json"):
                continue
            meta_path = os.path.join(evidence_artifacts_dir, entry)
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
            except Exception:
                meta = {}
            artifacts.append({
                "meta_name": entry,
                "meta_path": meta_path,
                "meta": meta
            })
    base["artifacts"] = artifacts
    return base

def register_reporting_routes(app):
    """
    Call this from your main Flask app after app = Flask(__name__)
    e.g. from modules.reporting import register_reporting_routes; register_reporting_routes(app)
    """
    bp = Blueprint("reporting", __name__, template_folder="../templates")

    @bp.route("/case/<case_id>/report", methods=["GET"])
    def report_preview(case_id):
        cid = _safe_case_id(case_id)
        if not cid:
            abort(404)
        files = _collect_case_files(cid)
        generated_at = datetime.datetime.utcnow().isoformat() + "Z"
        # Provide preview page with links to download PDF and ZIP
        return render_template(
            "report.html",
            case_id=cid,
            generated_at=generated_at,
            processes_exists=os.path.exists(files["processes_path"]),
            events_exists=os.path.exists(files["events_path"]),
            processes_path=files["processes_path"],
            events_path=files["events_path"],
            artifacts=files["artifacts"],
            pdf_url=url_for("reporting.report_pdf", case_id=cid),
            bundle_url=url_for("reporting.report_bundle", case_id=cid)
        )

    # Try importing Playwright; set to None if unavailable
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:
        sync_playwright = None

    @bp.route("/case/<case_id>/report.pdf", methods=["GET"])
    def report_pdf(case_id):
        cid = _safe_case_id(case_id)
        if not cid:
            abort(404)
        files = _collect_case_files(cid)

        # render HTML from template (same template used for preview)
        html = render_template(
            "report.html",
            case_id=cid,
            generated_at=datetime.datetime.utcnow().isoformat() + "Z",
            processes_exists=os.path.exists(files["processes_path"]),
            events_exists=os.path.exists(files["events_path"]),
            processes_path=files["processes_path"],
            events_path=files["events_path"],
            artifacts=files["artifacts"],
            pdf_mode=True,  # allow template to adjust for PDF (like page-breaks)
            pdf_url=url_for("reporting.report_pdf", case_id=cid),
            bundle_url=url_for("reporting.report_bundle", case_id=cid)
        )

        # Use Playwright to render HTML -> PDF
        if sync_playwright is None:
            current_app.logger.error("Playwright not available")
            abort(500, description="Playwright is not installed. Install 'playwright' and run 'python -m playwright install chromium'.")

        try:
            with sync_playwright() as pw:
                # headless Chromium (works cross-platform)
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox"] if os.environ.get("CI") else [])
                page = browser.new_page()
                # set content; networkidle ensures resources load if present
                page.set_content(html, wait_until="networkidle", timeout=30000)
                # generate PDF bytes (A4 portrait), include backgrounds
                pdf_bytes = page.pdf(format="A4", print_background=True)
                browser.close()
        except Exception as e:
            current_app.logger.exception("Playwright PDF generation failed")
            abort(500, description=f"PDF generation failed: {e}")

        # send as attachment
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{cid}_report.pdf"
        )

    @bp.route("/case/<case_id>/report_bundle.zip", methods=["GET"])
    def report_bundle(case_id):
        cid = _safe_case_id(case_id)
        if not cid:
            abort(404)
        files = _collect_case_files(cid)

        # render HTML
        html = render_template(
            "report.html",
            case_id=cid,
            generated_at=datetime.datetime.utcnow().isoformat() + "Z",
            processes_exists=os.path.exists(files["processes_path"]),
            events_exists=os.path.exists(files["events_path"]),
            processes_path=files["processes_path"],
            events_path=files["events_path"],
            artifacts=files["artifacts"],
            pdf_mode=True,
            pdf_url=url_for("reporting.report_pdf", case_id=cid),
            bundle_url=url_for("reporting.report_bundle", case_id=cid)
        )

        if sync_playwright is None:
            current_app.logger.error("Playwright not available")
            abort(500, description="Playwright is not installed. Install 'playwright' and run 'python -m playwright install chromium'.")

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox"] if os.environ.get("CI") else [])
                page = browser.new_page()
                page.set_content(html, wait_until="networkidle", timeout=30000)
                pdf_bytes = page.pdf(format="A4", print_background=True)
                browser.close()
        except Exception as e:
            current_app.logger.exception("Playwright PDF generation failed for ZIP")
            abort(500, description=f"PDF generation failed: {e}")

        # prepare manifest
        manifest = {
            "case_id": cid,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "files": []
        }

        # Build ZIP in memory
        inmem = io.BytesIO()
        with zipfile.ZipFile(inmem, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # add PDF
            pdf_name = f"{cid}_report.pdf"
            zf.writestr(pdf_name, pdf_bytes)
            manifest["files"].append({
                "name": pdf_name,
                "path": pdf_name,
                "size_bytes": len(pdf_bytes),
                "sha256": _sha256_bytes(pdf_bytes)
            })

            # add processes.csv and events.json if present
            for path, arcname in [(files["processes_path"], os.path.basename(files["processes_path"])),
                                   (files["events_path"], os.path.basename(files["events_path"]))]:
                if path and os.path.exists(path):
                    zf.write(path, arcname=arcname)
                    manifest["files"].append({
                        "name": arcname,
                        "path": arcname,
                        "size_bytes": os.path.getsize(path),
                        "sha256": _sha256_file(path)
                    })

            # add artifact metadata JSON files under artifacts/
            for art in files["artifacts"]:
                if os.path.exists(art["meta_path"]):
                    arcname = os.path.join("artifacts", art["meta_name"])
                    zf.write(art["meta_path"], arcname=arcname)
                    manifest["files"].append({
                        "name": art["meta_name"],
                        "path": arcname,
                        "size_bytes": os.path.getsize(art["meta_path"]),
                        "sha256": _sha256_file(art["meta_path"])
                    })

            # write manifest.json
            manifest_json = json.dumps(manifest, indent=2)
            zf.writestr("manifest.json", manifest_json)

        inmem.seek(0)
        return send_file(
            inmem,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"{cid}_report_bundle.zip"
        )

    # register blueprint
    app.register_blueprint(bp)
