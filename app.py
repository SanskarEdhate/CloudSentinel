import hashlib
import logging
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from import_public_data import DataImportError, sync_public_sources

csrf = CSRFProtect()
SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Open", "In Progress", "Resolved", "Closed")
CATEGORIES = (
    "Unauthorized Access",
    "Suspicious Login",
    "Malware",
    "Data Exposure",
    "Phishing",
    "Configuration Error",
    "API Abuse",
    "Other",
)
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "csv", "log"}


class LocalEvidenceStorage:
    """Private local file store. Keys are server-generated UUIDs, never paths."""

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, key, stream):
        if not re.fullmatch(r"[0-9a-f]{32}", key):
            raise ValueError("Invalid evidence key")
        destination = (self.root / key).resolve()
        if destination.parent != self.root:
            raise ValueError("Invalid evidence destination")
        digest = hashlib.sha256()
        size = 0
        with destination.open("xb") as output:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > current_app.config["MAX_CONTENT_LENGTH"]:
                    output.close()
                    destination.unlink(missing_ok=True)
                    raise RequestEntityTooLarge()
                digest.update(chunk)
                output.write(chunk)
        if not size:
            destination.unlink(missing_ok=True)
            raise ValueError("Evidence files cannot be empty")
        return size, digest.hexdigest()

    def open(self, key):
        if not re.fullmatch(r"[0-9a-f]{32}", key):
            abort(404)
        target = (self.root / key).resolve()
        if target.parent != self.root or not target.is_file():
            abort(404)
        return target.open("rb")

    def delete(self, key):
        if re.fullmatch(r"[0-9a-f]{32}", key):
            (self.root / key).unlink(missing_ok=True)


def create_app(test_config=None):
    load_dotenv(Path(__file__).resolve().with_name(".env"))
    app = Flask(__name__, instance_relative_config=True)
    try:
        max_content_length = int(os.getenv("MAX_CONTENT_LENGTH", str(10 * 1024 * 1024)))
        db_port = int(os.getenv("DB_PORT", "3306"))
    except ValueError as exc:
        raise RuntimeError("MAX_CONTENT_LENGTH and DB_PORT must be integers.") from exc
    if not 1 <= db_port <= 65535:
        raise RuntimeError("DB_PORT must be between 1 and 65535.")
    upload_folder = Path(os.getenv("UPLOAD_FOLDER") or "uploads")
    if not upload_folder.is_absolute():
        upload_folder = Path(app.root_path) / upload_folder
    app.config.from_mapping(
        SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
        DEBUG=os.getenv("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"},
        DATABASE=None,
        DB_HOST=os.getenv("DB_HOST", "127.0.0.1"),
        DB_PORT=db_port,
        DB_NAME=os.getenv("DB_NAME", "cloudsentinel"),
        DB_USER=os.getenv("DB_USER", "cloudsentinel"),
        DB_PASSWORD=os.getenv("DB_PASSWORD", ""),
        NVD_API_KEY=os.getenv("NVD_API_KEY", ""),
        ATTACK_CACHE_PATH=os.getenv(
            "ATTACK_CACHE_PATH",
            str(Path(app.root_path) / "data_cache" / "enterprise-attack.json"),
        ),
        UPLOAD_FOLDER=str(upload_folder),
        EVIDENCE_STORAGE=None,
        MAX_CONTENT_LENGTH=max_content_length,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0").lower()
        in {"1", "true", "yes"},
        PERMANENT_SESSION_LIFETIME=3600,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("FLASK_SECRET_KEY must be configured.")
    if app.config["MAX_CONTENT_LENGTH"] < 1:
        raise RuntimeError("MAX_CONTENT_LENGTH must be a positive number of bytes.")
    app.extensions["evidence_storage"] = app.config["EVIDENCE_STORAGE"] or LocalEvidenceStorage(
        app.config["UPLOAD_FOLDER"]
    )
    csrf.init_app(app)

    @app.context_processor
    def inject_globals():
        return {"current_year": datetime.now().year}

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please sign in to continue.", "warning")
                return redirect(url_for("login", next=request.path))
            account = query_one(
                "SELECT id, username, role, is_active FROM users WHERE id=?",
                (session["user_id"],),
            )
            if not account or not account["is_active"]:
                session.clear()
                flash("Your account is inactive. Contact an administrator.", "danger")
                return redirect(url_for("login"))
            session["username"] = account["username"]
            session["role"] = account["role"]
            return view(*args, **kwargs)

        return wrapped

    def roles_required(*roles):
        def decorator(view):
            @wraps(view)
            @login_required
            def wrapped(*args, **kwargs):
                if session.get("role") not in roles:
                    abort(403)
                return view(*args, **kwargs)

            return wrapped

        return decorator

    @contextmanager
    def connection():
        database = current_app.config.get("DATABASE")
        if database:
            conn = sqlite3.connect(database)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        else:
            conn = mysql.connector.connect(
                host=current_app.config["DB_HOST"],
                port=current_app.config["DB_PORT"],
                user=current_app.config["DB_USER"],
                password=current_app.config["DB_PASSWORD"],
                database=current_app.config["DB_NAME"],
                charset="utf8mb4",
                use_unicode=True,
                connection_timeout=5,
            )
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def execute(cursor, sql, params=()):
        if current_app.config.get("DATABASE"):
            return cursor.execute(sql, params)
        return cursor.execute(sql.replace("?", "%s"), params)

    def query_all(sql, params=()):
        with connection() as conn:
            cursor = conn.cursor() if current_app.config.get("DATABASE") else conn.cursor(dictionary=True)
            try:
                execute(cursor, sql, params)
                return [dict(row) for row in cursor.fetchall()] if current_app.config.get("DATABASE") else cursor.fetchall()
            finally:
                cursor.close()

    def query_one(sql, params=()):
        rows = query_all(sql, params)
        return rows[0] if rows else None

    def log_database_error(operation, error):
        errno = getattr(error, "errno", None)
        if type(errno) is not int:
            errno = "unknown"
        sqlstate = getattr(error, "sqlstate", None)
        if not isinstance(sqlstate, str) or not re.fullmatch(r"[0-9A-Z]{5}", sqlstate):
            sqlstate = "unknown"
        current_app.logger.error(
            "Database operation failed (operation=%s, driver=%s, errno=%s, sqlstate=%s)",
            operation,
            type(error).__name__,
            errno,
            sqlstate,
        )

    def run_transaction(callback):
        with connection() as conn:
            cursor = conn.cursor() if current_app.config.get("DATABASE") else conn.cursor(dictionary=True)
            try:
                return callback(cursor)
            finally:
                cursor.close()

    def audit(cursor, actor_id, action, entity_type=None, entity_id=None, details=""):
        execute(
            cursor,
            """INSERT INTO audit_logs
               (user_id, action, entity_type, entity_id, details)
               VALUES (?, ?, ?, ?, ?)""",
            (actor_id, action, entity_type, entity_id, details[:1000]),
        )

    def get_incident(incident_id):
        return query_one(
            """SELECT i.*, reporter.username AS reporter_name, assignee.username AS assignee_name
               FROM incidents i
               JOIN users reporter ON reporter.id=i.reporter_id
               LEFT JOIN users assignee ON assignee.id=i.assigned_to
               WHERE i.id=?""",
            (incident_id,),
        )

    def safe_next_url(candidate):
        if candidate and candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        return url_for("dashboard")

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if session.get("user_id") else "login"))

    @app.route("/health/database")
    def database_health():
        required_tables = (
            "users", "incidents", "audit_logs", "evidence", "vulnerabilities",
            "attack_objects", "network_observations", "source_sync_state",
        )
        try:
            with connection() as conn:
                cursor = conn.cursor() if current_app.config.get("DATABASE") else conn.cursor(dictionary=True)
                try:
                    for table in required_tables:
                        execute(cursor, f"SELECT 1 FROM {table} LIMIT 0")
                        cursor.fetchall()
                    execute(
                        cursor,
                        "SELECT id, username, password_hash, role, is_active "
                        "FROM users WHERE username=? LIMIT 1",
                        ("",),
                    )
                    cursor.fetchone()
                finally:
                    cursor.close()
        except (mysql.connector.Error, sqlite3.Error) as exc:
            log_database_error("health check", exc)
            return jsonify(status="unavailable"), 503
        return jsonify(status="ok")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            try:
                user = query_one(
                    "SELECT id, username, password_hash, role, is_active FROM users WHERE username=?",
                    (username,),
                )
            except (mysql.connector.Error, sqlite3.Error) as exc:
                log_database_error("login query", exc)
                flash("Unable to reach the database. Check the database settings and schema.", "danger")
                return render_template("login.html"), 503
            if user and user["is_active"] and check_password_hash(user["password_hash"], password):
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                run_transaction(
                    lambda cur: audit(cur, user["id"], "LOGIN", "user", user["id"], "Successful sign-in")
                )
                return redirect(safe_next_url(request.args.get("next")))
            flash("Invalid username/password or disabled account.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        uid = session["user_id"]
        run_transaction(lambda cur: audit(cur, uid, "LOGOUT", "user", uid, "Signed out"))
        session.clear()
        flash("You have signed out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        stats = query_one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN status='Open' THEN 1 ELSE 0 END) AS open_count,
                      SUM(CASE WHEN status='In Progress' THEN 1 ELSE 0 END) AS in_progress_count,
                      SUM(CASE WHEN status='Resolved' THEN 1 ELSE 0 END) AS resolved_count,
                      SUM(CASE WHEN status='Closed' THEN 1 ELSE 0 END) AS closed_count,
                      SUM(CASE WHEN severity='Critical' AND status NOT IN ('Resolved','Closed') THEN 1 ELSE 0 END) AS critical_count,
                      SUM(CASE WHEN severity='High' AND status NOT IN ('Resolved','Closed') THEN 1 ELSE 0 END) AS high_count
               FROM incidents"""
        )
        stats = {key: value or 0 for key, value in stats.items()}
        recent = query_all(
            """SELECT i.*, reporter.username AS reporter_name, assignee.username AS assignee_name
               FROM incidents i JOIN users reporter ON reporter.id=i.reporter_id
               LEFT JOIN users assignee ON assignee.id=i.assigned_to
               ORDER BY i.updated_at DESC LIMIT 8"""
        )
        severity_counts = query_all(
            "SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity"
        )
        status_counts = query_all("SELECT status, COUNT(*) AS count FROM incidents GROUP BY status")
        vulnerability_stats = query_one(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN is_kev=1 THEN 1 ELSE 0 END) AS kev_count
               FROM vulnerabilities"""
        )
        vulnerability_stats = {
            key: value or 0 for key, value in vulnerability_stats.items()
        }
        vulnerability_severity = query_all(
            """SELECT severity_label, COUNT(*) AS count
               FROM vulnerabilities GROUP BY severity_label"""
        )
        recent_vulnerabilities = query_all(
            """SELECT cve_id, description, published_at, severity_score, severity_label,
                      affected_products, is_kev, source_url
               FROM vulnerabilities
               ORDER BY published_at IS NULL, published_at DESC, cve_id DESC
               LIMIT 8"""
        )
        for vulnerability in recent_vulnerabilities:
            vulnerability["products"] = (
                vulnerability["affected_products"]
                or "Product not specified by source"
            )
        vulnerability_trends = query_all(
            """SELECT SUBSTR(published_at, 1, 7) AS month, COUNT(*) AS count
               FROM vulnerabilities
               WHERE published_at IS NOT NULL
               GROUP BY SUBSTR(published_at, 1, 7)
               ORDER BY month DESC LIMIT 6"""
        )
        attack_stats = query_one(
            """SELECT SUM(CASE WHEN object_type='tactic' THEN 1 ELSE 0 END) AS tactics,
                      SUM(CASE WHEN object_type='technique' THEN 1 ELSE 0 END) AS techniques
               FROM attack_objects"""
        )
        attack_stats = {key: value or 0 for key, value in attack_stats.items()}
        network_stats = query_one(
            """SELECT COUNT(*) AS flows, COALESCE(SUM(bytes), 0) AS bytes
               FROM network_observations"""
        )
        network_categories = query_all(
            """SELECT attack_category, COUNT(*) AS count
               FROM network_observations
               GROUP BY attack_category ORDER BY count DESC LIMIT 8"""
        )
        sync_state = query_all(
            """SELECT source_name, last_success_at, records_imported
               FROM source_sync_state ORDER BY source_name"""
        )
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        severity_distribution = [
            {
                "label": row["severity_label"] or "Unknown / not provided",
                "count": row["count"],
            }
            for row in vulnerability_severity
        ]
        severity_distribution.sort(
            key=lambda item: severity_order.get(item["label"].upper(), 4)
        )
        vulnerability_trends.reverse()
        return render_template(
            "dashboard.html",
            stats=stats,
            recent=recent,
            severity_counts={row["severity"]: row["count"] for row in severity_counts},
            status_counts={row["status"]: row["count"] for row in status_counts},
            vulnerability_stats=vulnerability_stats,
            vulnerability_severity=severity_distribution,
            recent_vulnerabilities=recent_vulnerabilities,
            vulnerability_trends=vulnerability_trends,
            attack_stats=attack_stats,
            network_stats=network_stats,
            network_categories=network_categories,
            sync_state={row["source_name"]: row for row in sync_state},
        )

    @app.route("/admin/data-sync", methods=["POST"])
    @roles_required("admin")
    def admin_data_sync():
        try:
            with connection() as conn:
                results = sync_public_sources(
                    conn,
                    api_key=current_app.config.get("NVD_API_KEY") or None,
                    attack_cache_path=current_app.config["ATTACK_CACHE_PATH"],
                )
        except DataImportError as exc:
            current_app.logger.error(
                "Public data synchronization failed (source=%s, error=%s)",
                exc.source,
                type(exc).__name__,
            )
            flash(f"Synchronization failed for {exc.source}; check the application log.", "danger")
            return redirect(url_for("dashboard"))
        except (mysql.connector.Error, sqlite3.Error) as exc:
            log_database_error("public data synchronization", exc)
            flash("Synchronization could not update the database; check the application log.", "danger")
            return redirect(url_for("dashboard"))
        run_transaction(
            lambda cur: audit(
                cur,
                session["user_id"],
                "PUBLIC_DATA_SYNC",
                "public_data",
                None,
                "Synchronized CISA KEV, NVD CVE, and MITRE ATT&CK",
            )
        )
        counts = ", ".join(
            f"{source}: {count}"
            for source, count in results.items()
            if not source.endswith("_download_bytes")
        )
        flash(f"Public-source synchronization complete ({counts}).", "success")
        return redirect(url_for("dashboard"))

    @app.route("/incidents")
    @login_required
    def incidents():
        search = request.args.get("q", "").strip()[:150]
        severity = request.args.get("severity", "")
        status = request.args.get("status", "")
        category = request.args.get("category", "")
        assignee = request.args.get("assignee", "")
        clauses, params = [], []
        if search:
            clauses.append("(i.title LIKE ? OR i.description LIKE ? OR i.category LIKE ? OR i.affected_resource LIKE ?)")
            params.extend([f"%{search}%"] * 4)
        if severity in SEVERITIES:
            clauses.append("i.severity=?")
            params.append(severity)
        if status in STATUSES:
            clauses.append("i.status=?")
            params.append(status)
        if category in CATEGORIES:
            clauses.append("i.category=?")
            params.append(category)
        if assignee.isdigit():
            clauses.append("i.assigned_to=?")
            params.append(int(assignee))
        sql = """SELECT i.*, reporter.username AS reporter_name, assignee.username AS assignee_name
                 FROM incidents i JOIN users reporter ON reporter.id=i.reporter_id
                 LEFT JOIN users assignee ON assignee.id=i.assigned_to"""
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY i.updated_at DESC"
        rows = query_all(sql, params)
        analysts = query_all(
            "SELECT id, username FROM users WHERE is_active=1 AND role='analyst' ORDER BY username"
        )
        return render_template(
            "incidents.html",
            incidents=rows,
            q=search,
            severity=severity,
            status=status,
            category=category,
            assignee=assignee,
            categories=CATEGORIES,
            severities=SEVERITIES,
            statuses=STATUSES,
            analysts=analysts,
        )

    def validate_incident(form):
        data = {
            "title": form.get("title", "").strip(),
            "description": form.get("description", "").strip(),
            "category": form.get("category", "").strip(),
            "severity": form.get("severity", ""),
            "status": form.get("status", "Open"),
            "affected_resource": form.get("affected_resource", "").strip(),
            "resolution_notes": form.get("resolution_notes", "").strip(),
        }
        errors = []
        if not data["title"] or len(data["title"]) > 180:
            errors.append("Title is required and must be at most 180 characters.")
        if not data["description"] or len(data["description"]) > 10000:
            errors.append("Description is required and must be at most 10,000 characters.")
        if data["category"] not in CATEGORIES:
            errors.append("Choose a valid incident category.")
        if data["severity"] not in SEVERITIES:
            errors.append("Choose a valid severity.")
        if data["status"] not in STATUSES:
            errors.append("Choose a valid status.")
        if len(data["affected_resource"]) > 255:
            errors.append("Affected resource must be at most 255 characters.")
        if len(data["resolution_notes"]) > 5000:
            errors.append("Resolution notes must be at most 5,000 characters.")
        detected = form.get("detection_at", "").strip()
        if detected:
            try:
                data["detection_at"] = datetime.fromisoformat(detected).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                errors.append("Detection time must be a valid date and time.")
                data["detection_at"] = None
        else:
            data["detection_at"] = None
        assigned = form.get("assigned_to", "").strip()
        data["assigned_to"] = int(assigned) if assigned.isdigit() else None
        if assigned and data["assigned_to"] is None:
            errors.append("Choose a valid assignee.")
        if data["assigned_to"] is not None:
            assignee = query_one(
                "SELECT id FROM users WHERE id=? AND role='analyst' AND is_active=1",
                (data["assigned_to"],),
            )
            if not assignee:
                errors.append("Assignee must be an active analyst account.")
        return data, errors

    def active_users():
        return query_all(
            "SELECT id, username FROM users WHERE is_active=1 AND role='analyst' ORDER BY username"
        )

    @app.route("/incidents/new", methods=["GET", "POST"])
    @login_required
    def new_incident():
        if request.method == "POST":
            data, errors = validate_incident(request.form)
            if errors:
                for message in errors:
                    flash(message, "danger")
                return render_template("incident_form.html", incident=data, analysts=active_users(), categories=CATEGORIES, severities=SEVERITIES), 400
            data["status"] = "Open"

            def create(cursor):
                execute(
                    cursor,
                    """INSERT INTO incidents
                       (title, description, category, severity, status, reporter_id, assigned_to,
                        affected_resource, detection_at, resolution_notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        data["title"], data["description"], data["category"], data["severity"],
                        data["status"], session["user_id"], data["assigned_to"],
                        data["affected_resource"] or None, data["detection_at"],
                        data["resolution_notes"] or None,
                    ),
                )
                incident_id = cursor.lastrowid
                audit(cursor, session["user_id"], "INCIDENT_CREATED", "incident", incident_id, data["title"])
                return incident_id

            incident_id = run_transaction(create)
            flash(f"Incident CS-{incident_id:04d} created.", "success")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        return render_template("incident_form.html", incident=None, analysts=active_users(), categories=CATEGORIES, severities=SEVERITIES)

    @app.route("/incidents/<int:incident_id>")
    @login_required
    def incident_detail(incident_id):
        incident = get_incident(incident_id)
        if not incident:
            abort(404)
        logs = query_all(
            """SELECT a.*, u.username FROM audit_logs a
               LEFT JOIN users u ON u.id=a.user_id
               WHERE a.entity_type='incident' AND a.entity_id=?
               ORDER BY a.created_at DESC LIMIT 50""",
            (incident_id,),
        )
        evidence = query_all(
            """SELECT e.*, u.username FROM evidence e JOIN users u ON u.id=e.uploaded_by
               WHERE e.incident_id=? ORDER BY e.uploaded_at DESC""",
            (incident_id,),
        )
        return render_template("incident_detail.html", incident=incident, logs=logs, evidence=evidence, analysts=active_users(), statuses=STATUSES, severities=SEVERITIES)

    @app.route("/incidents/<int:incident_id>/update", methods=["POST"])
    @login_required
    def update_incident(incident_id):
        old = get_incident(incident_id)
        if not old:
            abort(404)
        data, errors = validate_incident(request.form)
        if errors:
            for message in errors:
                flash(message, "danger")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        changes = []
        for field in ("status", "severity", "assigned_to", "title", "category", "description", "affected_resource", "detection_at", "resolution_notes"):
            old_value = old.get(field)
            new_value = data.get(field)
            if old_value != new_value and not (old_value is None and new_value == ""):
                changes.append(f"{field}: {old_value or '—'} → {new_value or '—'}")

        def update(cursor):
            execute(
                cursor,
                """UPDATE incidents SET title=?, description=?, category=?, severity=?, status=?,
                   assigned_to=?, affected_resource=?, detection_at=?, resolution_notes=?,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (
                    data["title"], data["description"], data["category"], data["severity"],
                    data["status"], data["assigned_to"], data["affected_resource"] or None,
                    data["detection_at"], data["resolution_notes"] or None, incident_id,
                ),
            )
            if changes:
                audit(cursor, session["user_id"], "INCIDENT_UPDATED", "incident", incident_id, "; ".join(changes))
            if old["status"] != data["status"]:
                audit(cursor, session["user_id"], "STATUS_CHANGED", "incident", incident_id, f"{old['status']} → {data['status']}")
            if old["assigned_to"] != data["assigned_to"]:
                audit(cursor, session["user_id"], "INCIDENT_ASSIGNED", "incident", incident_id, f"Assignee: {old['assignee_name'] or 'Unassigned'} → {data['assigned_to'] or 'Unassigned'}")

        run_transaction(update)
        flash("Incident updated.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    @app.route("/incidents/<int:incident_id>/delete", methods=["POST"])
    @roles_required("admin")
    def delete_incident(incident_id):
        incident = get_incident(incident_id)
        if not incident:
            abort(404)
        evidence = query_all("SELECT storage_key FROM evidence WHERE incident_id=?", (incident_id,))

        def delete(cursor):
            audit(cursor, session["user_id"], "INCIDENT_DELETED", "incident", incident_id, incident["title"])
            execute(cursor, "DELETE FROM incidents WHERE id=?", (incident_id,))

        run_transaction(delete)
        for item in evidence:
            app.extensions["evidence_storage"].delete(item["storage_key"])
        flash(f"Incident CS-{incident_id:04d} deleted.", "success")
        return redirect(url_for("incidents"))

    @app.route("/incidents/<int:incident_id>/evidence", methods=["POST"])
    @login_required
    def upload_evidence(incident_id):
        incident = get_incident(incident_id)
        if not incident:
            abort(404)
        uploaded = request.files.get("evidence")
        if not uploaded or not uploaded.filename:
            flash("Choose a file first.", "warning")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        original = secure_filename(uploaded.filename)
        extension = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        if not original or extension not in ALLOWED_EXTENSIONS:
            flash("Allowed file types: TXT, PDF, PNG, JPG, JPEG, CSV, LOG.", "danger")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        key = secrets.token_hex(16)
        try:
            size, checksum = app.extensions["evidence_storage"].save(key, uploaded.stream)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("incident_detail", incident_id=incident_id))
        try:
            def save_metadata(cursor):
                execute(
                    cursor,
                    """INSERT INTO evidence
                       (incident_id, original_name, storage_key, uploaded_by, size_bytes, sha256)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (incident_id, original, key, session["user_id"], size, checksum),
                )
                evidence_id = cursor.lastrowid
                audit(cursor, session["user_id"], "EVIDENCE_UPLOADED", "incident", incident_id, f"Evidence {evidence_id}: {original} ({size} bytes)")
            run_transaction(save_metadata)
        except Exception:
            app.extensions["evidence_storage"].delete(key)
            raise
        flash("Evidence uploaded.", "success")
        return redirect(url_for("incident_detail", incident_id=incident_id))

    @app.route("/evidence/<int:evidence_id>")
    @login_required
    def download_evidence(evidence_id):
        item = query_one("SELECT * FROM evidence WHERE id=?", (evidence_id,))
        if not item:
            abort(404)
        fileobj = app.extensions["evidence_storage"].open(item["storage_key"])
        run_transaction(
            lambda cursor: audit(
                cursor, session["user_id"], "EVIDENCE_DOWNLOADED", "incident",
                item["incident_id"], f"Evidence {evidence_id}: {item['original_name']}",
            )
        )
        response = send_file(fileobj, as_attachment=True, download_name=item["original_name"], mimetype="application/octet-stream")
        response.call_on_close(fileobj.close)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.route("/audit")
    @roles_required("admin")
    def audit_page():
        logs = query_all(
            """SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id
               ORDER BY a.created_at DESC LIMIT 250"""
        )
        return render_template("audit.html", logs=logs)

    @app.route("/users", methods=["GET", "POST"])
    @roles_required("admin")
    def users():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", username):
                flash("Username must be 3–80 letters, digits, dots, dashes, or underscores.", "danger")
            elif len(password) < 12 or len(password) > 128:
                flash("Password must be between 12 and 128 characters.", "danger")
            elif role not in {"admin", "analyst"}:
                flash("Choose a valid account role.", "danger")
            else:
                try:
                    def create_user(cursor):
                        execute(
                            cursor,
                            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                            (username, generate_password_hash(password), role),
                        )
                        new_user_id = cursor.lastrowid
                        audit(cursor, session["user_id"], "USER_CREATED", "user", new_user_id, f"Created {role} account {username}")
                    run_transaction(create_user)
                    flash("User created.", "success")
                    return redirect(url_for("users"))
                except (mysql.connector.IntegrityError, sqlite3.IntegrityError):
                    flash("That username is already in use.", "danger")
        rows = query_all("SELECT id, username, role, is_active, created_at FROM users ORDER BY id")
        return render_template("users.html", users=rows)

    @app.route("/users/<int:user_id>/update", methods=["POST"])
    @roles_required("admin")
    def update_user(user_id):
        target = query_one("SELECT id, username, role, is_active FROM users WHERE id=?", (user_id,))
        if not target:
            abort(404)
        role = request.form.get("role", "")
        active = request.form.get("is_active", "")
        if role not in {"admin", "analyst"} or active not in {"0", "1"}:
            abort(400)
        if user_id == session["user_id"] and (role != target["role"] or active != "1"):
            flash("You cannot change your own role or deactivate your own account.", "danger")
            return redirect(url_for("users"))
        if target["role"] == "admin" and target["is_active"] and (role != "admin" or active == "0"):
            admins = query_one("SELECT COUNT(*) AS count FROM users WHERE role='admin' AND is_active=1")
            if admins["count"] <= 1:
                flash("At least one active administrator must remain.", "danger")
                return redirect(url_for("users"))

        def change_user(cursor):
            execute(cursor, "UPDATE users SET role=?, is_active=? WHERE id=?", (role, int(active), user_id))
            if target["role"] != role:
                audit(cursor, session["user_id"], "USER_ROLE_CHANGED", "user", user_id, f"{target['role']} → {role}")
            if bool(target["is_active"]) != (active == "1"):
                audit(cursor, session["user_id"], "USER_STATUS_CHANGED", "user", user_id, "Activated" if active == "1" else "Deactivated")
        run_transaction(change_user)
        flash("User account updated.", "success")
        return redirect(url_for("users"))

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="The requested page was not found."), 404

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return render_template("error.html", code=413, message="Upload too large. Check the configured request size limit."), 413

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        return render_template("error.html", code=400, message="The form expired or its security token was invalid. Reload and try again."), 400

    @app.errorhandler(500)
    def internal_error(_error):
        current_app.logger.exception("Unhandled application error")
        return render_template("error.html", code=500, message="An unexpected error occurred."), 500

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(
        debug=app.config["DEBUG"],
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
    )
