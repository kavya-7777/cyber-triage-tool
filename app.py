# app.py
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, abort
import os
import json
from datetime import datetime

# --- Heuristics integration imports ---
from werkzeug.utils import secure_filename
# import analyzer (assumes heuristics.py is at project root or in PYTHONPATH)
from heuristics import analyze_file


# utils for file saves (keeps existing behavior)
from modules.utils import save_uploaded_file, ensure_case_dirs, iso_time_now
from werkzeug.exceptions import RequestEntityTooLarge
from modules.hashing import compute_sha256, update_artifact_hash
from modules.ioc import check_iocs_for_artifact
from modules.yara import scan_artifact as yara_scan_artifact, compile_rules as yara_compile_rules

# DB
from modules.db import db

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "evidence"
# ---------------------------
# App config: upload limits, allowed extensions & logging
# ---------------------------
# Max upload size: 100 MB (adjust as needed). This prevents huge uploads in demo.
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# Allowed extensions (None = allow all). Example: {'exe','dll','txt','log'}
ALLOWED_EXTENSIONS = None  # change to a set like {'exe','txt'} to restrict

# Setup basic logging
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cyber-triage")


# ---------------------------
# Robust DB path setup
# ---------------------------
# Use an absolute path for the SQLite file so the DB is always created under the project data/ folder.
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
os.makedirs(DATA_DIR, exist_ok=True)

db_path = os.path.join(DATA_DIR, "triage.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Ensure base evidence dir exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# init DB (db is defined in modules/db.py)
db.init_app(app)

# import models AFTER db.init_app to avoid circular import issues
with app.app_context():
    from modules import models  # registers models with SQLAlchemy
    # create tables if they don't exist
    db.create_all()
    Case = models.Case
    Artifact = models.Artifact


# -------------------------
# Manifest helpers (keeps existing JSON manifest side-by-side)
# -------------------------
def manifest_path_for_case(case_id):
    case_dir = os.path.join(app.config["UPLOAD_FOLDER"], case_id)
    return os.path.join(case_dir, "manifest.json")


def load_manifest(case_id):
    manifest_p = manifest_path_for_case(case_id)
    if os.path.exists(manifest_p):
        with open(manifest_p, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "case_id": case_id,
        "created_at": iso_time_now(),
        "artifacts": []
    }


def save_manifest(case_id, manifest):
    """
    Atomically write manifest.json for a case to avoid partial-write races.
    """
    case_dir, _ = ensure_case_dirs(case_id)
    manifest_p = manifest_path_for_case(case_id)
    temp_path = manifest_p + ".tmp"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        # atomic replace
        os.replace(temp_path, manifest_p)
    except Exception:
        logger.exception("Failed to write manifest atomically")
        # cleanup temp file if present
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
        raise



def add_artifact_to_manifest(case_id, artifact_metadata):
    manifest = load_manifest(case_id)
    summary = {
        "artifact_id": artifact_metadata.get("artifact_id"),
        "original_filename": artifact_metadata.get("original_filename"),
        "saved_filename": artifact_metadata.get("saved_filename"),
        "saved_path": artifact_metadata.get("saved_path"),
        "uploaded_by": artifact_metadata.get("uploaded_by"),
        "uploaded_at": artifact_metadata.get("uploaded_at"),
        "size_bytes": artifact_metadata.get("size_bytes"),
        "analysis": artifact_metadata.get("analysis")
    }
    manifest["artifacts"].append(summary)
    save_manifest(case_id, manifest)
    return manifest


# -------------------------
# Routes
# -------------------------
@app.route("/")
def home():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    """
    Save file to disk (modules.utils.save_uploaded_file), compute SHA-256,
    update manifest, and create/update DB records.
    Auto-runs IOC and YARA checks (if available) and refreshes response metadata.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    case_id = request.form.get("case_id", "case001").strip() or "case001"
    uploader = request.form.get("uploader", "investigator").strip() or "investigator"

    # 1) Save file to disk and write artifact JSON (existing behavior)
    try:
        # Note: save_uploaded_file uses secure_filename and can accept allowed_ext_set if configured
        metadata = save_uploaded_file(file, case_id=case_id, uploader=uploader, allowed_ext_set=ALLOWED_EXTENSIONS)
    except ValueError as ve:
        logger.warning("Upload blocked: %s", ve)
        return jsonify({"error": str(ve)}), 400
    except Exception:
        logger.exception("Upload failed while saving file")
        return jsonify({"error": "Failed to save uploaded file"}), 500

    # 2) Update manifest.json (keeps file-based backup)
    try:
        manifest = add_artifact_to_manifest(case_id, metadata)
    except Exception:
        logger.exception("Failed to update manifest after upload")
        return jsonify({"error": "Failed to update manifest"}), 500

    # 3) Write into DB: create Case if missing, then Artifact row
    try:
        case = Case.query.filter_by(case_id=case_id).first()
        if not case:
            case = Case(case_id=case_id)
            db.session.add(case)
            db.session.commit()  # commit to ensure case exists before FK use

        # Parse uploaded_at into datetime for DB (remove trailing Z)
        uploaded_at_str = metadata.get("uploaded_at")
        if uploaded_at_str and uploaded_at_str.endswith("Z"):
            uploaded_at_dt = datetime.fromisoformat(uploaded_at_str[:-1])
        else:
            uploaded_at_dt = datetime.utcnow()

        artifact = Artifact(
            artifact_id=metadata.get("artifact_id"),
            case_id=case_id,
            original_filename=metadata.get("original_filename"),
            saved_filename=metadata.get("saved_filename"),
            saved_path=metadata.get("saved_path"),
            uploaded_by=metadata.get("uploaded_by"),
            uploaded_at=uploaded_at_dt,
            size_bytes=metadata.get("size_bytes"),
            analysis=None
        )
        db.session.add(artifact)
        db.session.commit()
    except Exception:
        logger.exception("Failed to insert artifact record into DB")
        return jsonify({"error": "Failed to record artifact in database"}), 500

    # 4) Compute SHA-256, update artifact metadata + manifest + DB
    try:
        sha256_hex = compute_sha256(metadata["saved_path"])
        update_artifact_hash(case_id, metadata["artifact_id"], sha256_hex)

        # add sha256 to the metadata that we return to the client
        metadata["sha256"] = sha256_hex

        # --- AUTO IOC CHECK (run immediately after hash update) ---
        try:
            try:
                ioc_result = check_iocs_for_artifact(case_id, metadata["artifact_id"])
                # attach to returned metadata for immediate visibility
                metadata["ioc_matches"] = ioc_result.get("matches", [])
            except FileNotFoundError as fe:
                logger.warning("IOC check: metadata/file not found for %s/%s: %s", case_id, metadata.get("artifact_id"), fe)
            except Exception:
                logger.exception("Auto IOC check failed for %s/%s", case_id, metadata.get("artifact_id"))
        except ImportError:
            # safety: if module import is somehow missing
            logger.info("IOC module not present; skipping auto IOC check")
        # --- end AUTO IOC CHECK ---

        # --- AUTO YARA SCAN (run after hash & IOC) ---
        try:
            try:
                yara_result = yara_scan_artifact(case_id, metadata["artifact_id"])
                # if yara module not available or compilation failed, yara_result will include an error
                if yara_result:
                    # attach yara result summary into the response metadata for immediate visibility
                    metadata["yara_matches"] = yara_result.get("matches", [])
                    # also include availability flag if present
                    if "yara_available" in yara_result:
                        metadata["yara_available"] = yara_result.get("yara_available")
            except Exception:
                logger.exception("Auto YARA scan failed for %s/%s", case_id, metadata.get("artifact_id"))
        except ImportError:
            logger.info("YARA module not present; skipping auto YARA scan")
        # --- end AUTO YARA ---

        # --- AUTO HEURISTICS ANALYSIS (new) ---
        try:
            try:
                heuristics_report = analyze_file(metadata["saved_path"])
                # attach heuristics to metadata for immediate visibility
                metadata["heuristics"] = heuristics_report

                # Persist heuristics report into DB Artifact.analysis (JSON) and artifact JSON file
                try:
                    # Save into DB artifact.analysis (merge with any existing analysis)
                    db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
                    if db_artifact:
                        # Merge existing analysis if present
                        existing = {}
                        try:
                            if db_artifact.analysis:
                                existing = json.loads(db_artifact.analysis) if isinstance(db_artifact.analysis, str) else db_artifact.analysis
                        except Exception:
                            existing = {}

                        # Attach heuristics under a key (keep other analysis like IOC/YARA)
                        existing.setdefault("heuristics", heuristics_report)
                        db_artifact.analysis = json.dumps(existing)
                        db.session.add(db_artifact)
                        db.session.commit()
                        # ensure metadata returned includes analysis
                        metadata["analysis"] = existing
                    else:
                        # If DB record missing (unlikely), fallback to writing artifact-side JSON
                        metadata["analysis"] = {"heuristics": heuristics_report}

                    # Also write to artifact JSON file adjacent to saved artifact
                    meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                    try:
                        on_disk_meta = {}
                        if os.path.exists(meta_path):
                            with open(meta_path, "r", encoding="utf-8") as fh:
                                on_disk_meta = json.load(fh)
                        on_disk_meta.setdefault("analysis", {})
                        on_disk_meta["analysis"].setdefault("heuristics", heuristics_report)
                        with open(meta_path, "w", encoding='utf-8') as fh:
                            json.dump(on_disk_meta, fh, indent=2)
                    except Exception:
                        logger.exception("Failed to write heuristics into artifact JSON on disk for %s", metadata.get("artifact_id"))

                except Exception:
                    logger.exception("Failed to persist heuristics analysis to DB for %s", metadata.get("artifact_id"))

            except Exception:
                logger.exception("Auto heuristics analysis failed for %s/%s", case_id, metadata.get("artifact_id"))
        except ImportError:
            # If import at top fails (shouldn't because you imported), log and continue
            logger.info("Heuristics module not present; skipping heuristics analysis")
        # --- end AUTO HEURISTICS ---


        # --- Update manifest.json with heuristics (new) ---
        try:
            m = load_manifest(case_id)
            # find artifact entry in manifest by artifact_id
            for entry in m.get("artifacts", []):
                if entry.get("artifact_id") == metadata.get("artifact_id"):
                    entry["analysis"] = metadata.get("analysis", entry.get("analysis"))
                    if metadata.get("heuristics"):
                        entry.setdefault("analysis", {})
                        entry["analysis"].setdefault("heuristics", metadata["heuristics"])
                        # also store suspicion_score at top-level for quick dashboard/summary use
                        entry["suspicion_score"] = metadata["heuristics"].get("suspicion_score")
                    break
            save_manifest(case_id, m)
        except Exception:
            logger.exception("Failed to update manifest.json with heuristics for %s", metadata.get("artifact_id"))
        # --- end manifest update ---

                # --- Compute final suspicion score combining IOC/YARA/HEURISTICS ---
        try:
            from modules.scoring import compute_final_score
            analysis_blob = metadata.get("analysis") or {}

            # run scoring (this normalizedly reads ioc/yara/heuristics)
            final = compute_final_score(analysis_blob)

            # attach results into metadata.analysis
            metadata.setdefault("analysis", {})
            metadata["analysis"]["final_score"] = final.get("final_score")
            metadata["analysis"]["final_breakdown"] = final.get("breakdown")
            metadata["analysis"]["final_reasons"] = final.get("reasons")

            # Persist into DB record (Artifact.analysis): merge with existing analysis
            try:
                db_art = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
                if db_art:
                    existing = {}
                    if db_art.analysis:
                        try:
                            existing = json.loads(db_art.analysis) if isinstance(db_art.analysis, str) else db_art.analysis
                        except Exception:
                            existing = {}
                    # merge/overwrite analysis keys with final score values
                    existing.update(metadata["analysis"])
                    db_art.analysis = json.dumps(existing)
                    db.session.add(db_art)
                    db.session.commit()
            except Exception:
                logger.exception("Failed to persist final score to DB for %s", metadata.get("artifact_id"))

            # Also update artifact JSON file (atomic write)
            try:
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                on_disk_meta = {}
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path, "r", encoding="utf-8") as fh:
                            on_disk_meta = json.load(fh)
                    except Exception:
                        on_disk_meta = {}
                on_disk_meta.setdefault("analysis", {})
                # merge final analysis keys
                on_disk_meta["analysis"].update(metadata["analysis"])
                tmp = meta_path + ".tmp"
                with open(tmp, "w", encoding='utf-8') as fh:
                    json.dump(on_disk_meta, fh, indent=2)
                os.replace(tmp, meta_path)
            except Exception:
                logger.exception("Failed to write final score into artifact JSON on disk for %s", metadata.get("artifact_id"))

            # Update manifest entry for this artifact (if present)
            try:
                m = load_manifest(case_id)
                changed = False
                for entry in m.get("artifacts", []):
                    if entry.get("artifact_id") == metadata.get("artifact_id"):
                        entry["analysis"] = metadata.get("analysis")
                        # also keep a top-level compatibility field used by UI
                        entry["suspicion_score"] = metadata["analysis"].get("final_score")
                        changed = True
                        break
                if changed:
                    save_manifest(case_id, m)
            except Exception:
                logger.exception("Failed to update manifest with final score for %s", metadata.get("artifact_id"))

        except Exception:
            logger.exception("Failed to compute/persist final suspicion score for %s", metadata.get("artifact_id"))
        # --- end final score ---


        # After running IOC and YARA (which update JSON/DB), refresh analysis from DB or file
        try:
            db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
            if db_artifact and db_artifact.analysis:
                try:
                    metadata["analysis"] = json.loads(db_artifact.analysis)
                except Exception:
                    metadata["analysis"] = db_artifact.analysis
            else:
                # fallback: read artifact metadata JSON on disk
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        file_meta = json.load(f)
                    metadata["analysis"] = file_meta.get("analysis")
                else:
                    metadata["analysis"] = None
        except Exception:
            # if anything goes wrong reading DB, try reading file and otherwise leave null
            try:
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                if os.path.exists(meta_path):
                    with open(meta_path, "r", encoding="utf-8") as f:
                        file_meta = json.load(f)
                    metadata["analysis"] = file_meta.get("analysis")
                else:
                    metadata["analysis"] = None
            except Exception:
                metadata["analysis"] = None

    except Exception:
        logger.exception("Hashing or update failed for %s", metadata.get("artifact_id"))

    # Return both metadata and DB id for convenience
    return jsonify({
        "status": "saved",
        "metadata": metadata,
        "db_artifact_id": artifact.id,
        "manifest_summary_count": len(manifest["artifacts"])
    })


@app.route("/dashboard")
def dashboard():
    """
    Dashboard: show case-level info (from DB) and artifacts list.
    Accepts optional ?case_id= parameter.
    """
    case_id = request.args.get("case_id", "case001")

    # Try to load case from DB; if missing fall back to manifest count
    case = Case.query.filter_by(case_id=case_id).first()
    if case:
        artifact_rows = Artifact.query.filter_by(case_id=case_id).order_by(Artifact.uploaded_at.desc()).all()
        artifacts = [r.to_dict() for r in artifact_rows]
        artifact_count = len(artifacts)
        case_info = case.to_dict()
    else:
        # fallback: existing manifest behavior (no DB case present)
        manifest = load_manifest(case_id)
        artifacts = manifest.get("artifacts", [])
        artifact_count = len(artifacts)
        case_info = {"case_id": case_id, "created_at": None, "artifact_count": artifact_count}

    # Render template with artifacts read from DB (or fallback)
    return render_template(
        "dashboard.html",
        case_id=case_id,
        artifact_count=artifact_count,
        suspicion_score=0,
        artifacts=artifacts,
        case_info=case_info
    )


@app.route("/timeline")
def timeline():
    case_id = request.args.get("case_id", "case001")
    manifest = load_manifest(case_id)
    return render_template("timeline.html", case_id=case_id, artifacts=manifest.get("artifacts", []))


@app.route("/report")
def report():
    """
    Report preview: collect case & artifacts from DB (preferred) or manifest (fallback)
    and render templates/report.html for preview. Later this will be converted to PDF.
    """
    case_id = request.args.get("case_id", "case001")

    # Try DB first
    case = Case.query.filter_by(case_id=case_id).first()
    if case:
        artifacts_rows = Artifact.query.filter_by(case_id=case_id).order_by(Artifact.uploaded_at.desc()).all()
        artifacts = [r.to_dict() for r in artifacts_rows]
        case_info = case.to_dict()
    else:
        # fallback to manifest JSON
        manifest = load_manifest(case_id)
        artifacts = manifest.get("artifacts", [])
        case_info = {"case_id": case_id, "created_at": None, "artifact_count": len(artifacts)}

    # Render the report template (report.html) with structured data
    return render_template("report.html", case_id=case_id, case_info=case_info, artifacts=artifacts)


@app.route("/heuristics", methods=["GET", "POST"])
def heuristics_upload():
    """
    Ad-hoc UI: upload a file (choose a case_id if desired) to run heuristics analysis.
    Renders templates/heuristics_upload.html (create this template — I provided earlier).
    """
    if request.method == "POST":
        # reuse your existing save_uploaded_file helper that accepts file + case_id
        file = request.files.get("file")
        case_id = request.form.get("case_id", "case001")
        uploader = request.form.get("uploader", "investigator")
        if not file:
            flash("No file provided", "danger")
            return redirect(request.url)
        try:
            metadata = save_uploaded_file(file, case_id=case_id, uploader=uploader, allowed_ext_set=ALLOWED_EXTENSIONS)
        except Exception as e:
            logger.exception("Upload failed in /heuristics")
            flash(f"Upload failed: {e}", "danger")
            return redirect(request.url)

        # Run heuristics
        try:
            heuristics_report = analyze_file(metadata["saved_path"])
            metadata["heuristics"] = heuristics_report
            # Persist heuristics into DB and artifact JSON (same approach as upload_file)
            try:
                db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
                existing = {}
                if db_artifact:
                    try:
                        if db_artifact.analysis:
                            existing = json.loads(db_artifact.analysis) if isinstance(db_artifact.analysis, str) else db_artifact.analysis
                    except Exception:
                        existing = {}
                    existing.setdefault("heuristics", heuristics_report)
                    db_artifact.analysis = json.dumps(existing)
                    db.session.add(db_artifact)
                    db.session.commit()
                    metadata["analysis"] = existing
                else:
                    metadata["analysis"] = {"heuristics": heuristics_report}
                # write artifact JSON file
                meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
                on_disk_meta = {}
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path, "r", encoding="utf-8") as fh:
                            on_disk_meta = json.load(fh)
                    except Exception:
                        on_disk_meta = {}
                on_disk_meta.setdefault("analysis", {})
                on_disk_meta["analysis"].setdefault("heuristics", heuristics_report)
                with open(meta_path, "w", encoding="utf-8") as fh:
                    json.dump(on_disk_meta, fh, indent=2)
            except Exception:
                logger.exception("Failed to persist heuristics from /heuristics upload")
        except Exception:
            logger.exception("Heuristics analysis failed in /heuristics")
            flash("Heuristics analysis failed; see server logs", "warning")
            return redirect(request.url)

        # Render result page
        return render_template("heuristics_upload.html", report=metadata.get("heuristics"), metadata=metadata)

    # GET
    return render_template("heuristics_upload.html", report=None, metadata=None)


@app.route("/api/heuristics", methods=["POST"])
def heuristics_api():
    """
    Programmatic API: accept multipart form-data field 'file' and optional 'case_id' & 'uploader'.
    Returns the heuristics report JSON and persists it similarly to the upload flow.
    """
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "no file provided"}), 400
    case_id = request.form.get("case_id", "case001")
    uploader = request.form.get("uploader", "investigator")
    try:
        metadata = save_uploaded_file(file, case_id=case_id, uploader=uploader, allowed_ext_set=ALLOWED_EXTENSIONS)
    except ValueError as ve:
        logger.warning("Upload blocked in API: %s", ve)
        return jsonify({"error": str(ve)}), 400
    except Exception:
        logger.exception("Upload failed in API /api/heuristics")
        return jsonify({"error": "failed to save uploaded file"}), 500

    try:
        heuristics_report = analyze_file(metadata["saved_path"])
        metadata["heuristics"] = heuristics_report
    except Exception:
        logger.exception("Heuristics analysis failed in API")
        return jsonify({"error": "heuristics analysis failed"}), 500

    # Persist to DB + artifact JSON
    try:
        db_artifact = Artifact.query.filter_by(artifact_id=metadata["artifact_id"]).first()
        existing = {}
        if db_artifact:
            try:
                if db_artifact.analysis:
                    existing = json.loads(db_artifact.analysis) if isinstance(db_artifact.analysis, str) else db_artifact.analysis
            except Exception:
                existing = {}
            existing.setdefault("heuristics", heuristics_report)
            db_artifact.analysis = json.dumps(existing)
            db.session.add(db_artifact)
            db.session.commit()
            metadata["analysis"] = existing
        else:
            metadata["analysis"] = {"heuristics": heuristics_report}
        # write artifact JSON file
        meta_path = os.path.join(os.path.dirname(metadata["saved_path"]), f"{metadata['artifact_id']}.json")
        on_disk_meta = {}
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    on_disk_meta = json.load(fh)
            except Exception:
                on_disk_meta = {}
        on_disk_meta.setdefault("analysis", {})
        on_disk_meta["analysis"].setdefault("heuristics", heuristics_report)
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(on_disk_meta, fh, indent=2)
    except Exception:
        logger.exception("Failed to persist heuristics in API for %s", metadata.get("artifact_id"))

    return jsonify({"status": "ok", "heuristics": heuristics_report, "metadata": metadata})




@app.route("/test-analysis")
def test_analysis():
    return "Test analysis route (no-op for upload demo)."


@app.route("/artifact/<case_id>/<artifact_filename>")
def download_artifact(case_id, artifact_filename):
    _, artifacts_dir = ensure_case_dirs(case_id)
    safe_path = os.path.join(artifacts_dir, artifact_filename)
    if not os.path.exists(safe_path):
        abort(404)
    return send_file(safe_path, as_attachment=True)


@app.route("/api/manifest/<case_id>")
def api_manifest(case_id):
    manifest = load_manifest(case_id)
    return jsonify(manifest)


# Optional: API endpoints to query DB records (for later frontend usage)
@app.route("/api/db/case/<case_id>")
def api_db_case(case_id):
    case = Case.query.filter_by(case_id=case_id).first()
    if not case:
        return jsonify({"error": "case not found"}), 404
    return jsonify(case.to_dict())


@app.route("/api/db/artifacts/<case_id>")
def api_db_artifacts(case_id):
    rows = Artifact.query.filter_by(case_id=case_id).all()
    return jsonify([r.to_dict() for r in rows])

@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({"error": "Uploaded file is too large"}), 413

@app.route("/api/ioc_check/<case_id>/<artifact_id>", methods=["GET", "POST"])
def api_ioc_check(case_id, artifact_id):
    """
    Trigger IOC matching for a single artifact and return the matches.
    """
    try:
        result = check_iocs_for_artifact(case_id, artifact_id)
        return jsonify({"status": "ok", "result": result})
    except FileNotFoundError as e:
        return jsonify({"status": "error", "error": str(e)}), 404
    except Exception as e:
        logger.exception("IOC check failed for %s/%s", case_id, artifact_id)
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/yara_check/<case_id>/<artifact_id>", methods=["GET", "POST"])
def api_yara_check(case_id, artifact_id):
    """
    Trigger YARA scan for a single artifact and return matches.
    """
    try:
        result = yara_scan_artifact(case_id, artifact_id)
        if result.get("error"):
            return jsonify({"status": "error", "error": result.get("error"), "result": result}), 500
        return jsonify({"status": "ok", "result": result})
    except Exception as e:
        logger.exception("YARA API check failed for %s/%s", case_id, artifact_id)
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/recompute_score/<case_id>/<artifact_id>", methods=["POST", "GET"])
def api_recompute_score(case_id, artifact_id):
    """
    Recompute IOC, YARA and Heuristics for a single artifact then compute & persist final score.
    - Runs: check_iocs_for_artifact, yara_scan_artifact, analyze_file (heuristics), compute_final_score
    - Persists results to: artifact JSON file (evidence/<case>/artifacts/<artifact_id>.json),
      case manifest, and DB Artifact.analysis
    Returns: JSON with final_score, breakdown and component details.
    """
    try:
        # 1) locate artifact JSON on disk
        _, artifacts_dir = ensure_case_dirs(case_id)
        meta_path = os.path.join(artifacts_dir, f"{artifact_id}.json")
        if not os.path.exists(meta_path):
            return jsonify({"status": "error", "error": "artifact metadata not found", "path": meta_path}), 404

        # load artifact metadata
        try:
            with open(meta_path, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        except Exception as e:
            logger.exception("Failed to load artifact metadata for recompute %s/%s", case_id, artifact_id)
            return jsonify({"status": "error", "error": f"failed to load metadata: {e}"}), 500

        saved_path = meta.get("saved_path")
        # fallback: find file by prefix if saved_path missing
        if (not saved_path or not os.path.exists(saved_path)) and os.path.exists(artifacts_dir):
            for fn in os.listdir(artifacts_dir):
                if fn.startswith(artifact_id + "__"):
                    saved_path = os.path.join(artifacts_dir, fn)
                    break

        # 2) recompute SHA (if necessary) and ensure metadata sha present
        try:
            if saved_path and os.path.exists(saved_path):
                from modules.hashing import compute_sha256, update_artifact_hash
                sha = meta.get("sha256")
                if not sha:
                    sha = compute_sha256(saved_path)
                    meta["sha256"] = sha
                    # ensure DB/manifest updated by calling update_artifact_hash helper
                    try:
                        update_artifact_hash(case_id, artifact_id, sha)
                    except Exception:
                        logger.debug("update_artifact_hash failed (ok) during recompute for %s", artifact_id)
        except Exception:
            logger.exception("failed to compute sha during recompute for %s/%s", case_id, artifact_id)

        # 3) re-run IOC
        ioc_matches = []
        try:
            ioc_res = check_iocs_for_artifact(case_id, artifact_id)
            ioc_matches = ioc_res.get("matches", []) if isinstance(ioc_res, dict) else []
            meta.setdefault("analysis", {}).setdefault("ioc_matches", ioc_matches)
        except FileNotFoundError:
            # artifact missing/inconsistent
            logger.warning("IOC recompute: artifact metadata not found for %s/%s", case_id, artifact_id)
        except Exception:
            logger.exception("IOC recompute failed for %s/%s", case_id, artifact_id)

        # 4) re-run YARA
        yara_matches = []
        try:
            yara_res = yara_scan_artifact(case_id, artifact_id)
            if isinstance(yara_res, dict):
                yara_matches = yara_res.get("matches", []) or []
                # also record yara_available flag if present
                if "yara_available" in yara_res:
                    meta.setdefault("analysis", {})["yara_available"] = yara_res.get("yara_available")
                meta.setdefault("analysis", {})["yara_matches"] = yara_matches
        except Exception:
            logger.exception("YARA recompute failed for %s/%s", case_id, artifact_id)

        # 5) re-run heuristics (optional but recommended to refresh heuristics results)
        heuristics_report = {}
        try:
            if saved_path and os.path.exists(saved_path):
                heuristics_report = analyze_file(saved_path)
                meta.setdefault("analysis", {})["heuristics"] = heuristics_report
        except Exception:
            logger.exception("Heuristics recompute failed for %s/%s", case_id, artifact_id)

        # 6) compute final score
        try:
            from modules.scoring import compute_final_score
            final = compute_final_score(meta.get("analysis") or meta)
            # attach final results to meta.analysis
            meta.setdefault("analysis", {})
            meta["analysis"]["final_score"] = final.get("final_score")
            meta["analysis"]["final_breakdown"] = final.get("breakdown")
            meta["analysis"]["final_reasons"] = final.get("reasons")
        except Exception:
            logger.exception("Final scoring failed for %s/%s", case_id, artifact_id)
            return jsonify({"status": "error", "error": "scoring failed"}), 500

        # 7) persist changes: artifact JSON (atomic)
        try:
            tmp = meta_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2)
            os.replace(tmp, meta_path)
        except Exception:
            logger.exception("Failed to write updated artifact metadata for %s/%s", case_id, artifact_id)

        # 8) persist to DB (Artifact.analysis)
        try:
            art = Artifact.query.filter_by(artifact_id=artifact_id).first()
            if art:
                existing = {}
                if art.analysis:
                    try:
                        existing = json.loads(art.analysis)
                    except Exception:
                        existing = {}
                # merge
                existing.update(meta.get("analysis", {}))
                art.analysis = json.dumps(existing)
                db.session.add(art)
                db.session.commit()
        except Exception:
            logger.exception("Failed to update DB analysis for %s/%s", case_id, artifact_id)

        # 9) update manifest entry
        try:
            manifest = load_manifest(case_id)
            changed = False
            for entry in manifest.get("artifacts", []):
                if entry.get("artifact_id") == artifact_id:
                    entry["analysis"] = meta.get("analysis")
                    entry["suspicion_score"] = meta.get("analysis", {}).get("final_score")
                    changed = True
                    break
            if changed:
                save_manifest(case_id, manifest)
        except Exception:
            logger.exception("Failed to update manifest for %s/%s", case_id, artifact_id)

        # 10) return structured result
        return jsonify({
            "status": "ok",
            "artifact_id": artifact_id,
            "case_id": case_id,
            "final_score": meta.get("analysis", {}).get("final_score"),
            "final_breakdown": meta.get("analysis", {}).get("final_breakdown"),
            "final_reasons": meta.get("analysis", {}).get("final_reasons"),
            "ioc_matches": ioc_matches,
            "yara_matches": yara_matches,
            "heuristics": heuristics_report
        })
    except Exception:
        logger.exception("Unexpected error during recompute for %s/%s", case_id, artifact_id)
        return jsonify({"status": "error", "error": "unexpected server error"}), 500


if __name__ == "__main__":
    app.run(debug=True)
