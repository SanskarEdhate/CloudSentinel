import io
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import mysql.connector
from werkzeug.security import generate_password_hash

from app import create_app


SQLITE_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst',
 is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE incidents (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL,
 category TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
 reporter_id INTEGER NOT NULL, assigned_to INTEGER, affected_resource TEXT,
 detection_at TEXT, resolution_notes TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(reporter_id) REFERENCES users(id),
 FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL,
 entity_type TEXT, entity_id INTEGER, details TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE evidence (
 id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
 original_name TEXT NOT NULL, storage_key TEXT NOT NULL UNIQUE, uploaded_by INTEGER NOT NULL,
 size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
 FOREIGN KEY(uploaded_by) REFERENCES users(id)
);
CREATE TABLE vulnerabilities (
 cve_id TEXT PRIMARY KEY, source_name TEXT NOT NULL, source_identifier TEXT NOT NULL,
 source_url TEXT NOT NULL, description TEXT, published_at TEXT, modified_at TEXT,
 severity_score REAL, severity_label TEXT, affected_products TEXT,
 is_kev INTEGER NOT NULL DEFAULT 0, kev_source_name TEXT,
 kev_source_identifier TEXT, kev_source_url TEXT, kev_date_added TEXT, kev_due_date TEXT,
 kev_required_action TEXT, kev_ransomware_use TEXT, imported_at TEXT
);
CREATE TABLE attack_objects (
 stix_id TEXT PRIMARY KEY, external_id TEXT NOT NULL UNIQUE, object_type TEXT NOT NULL,
 name TEXT NOT NULL, description TEXT, tactic_shortname TEXT, source_name TEXT NOT NULL,
 source_identifier TEXT NOT NULL, source_url TEXT NOT NULL, published_at TEXT,
 modified_at TEXT, imported_at TEXT
);
CREATE TABLE network_observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, source_identifier TEXT NOT NULL UNIQUE,
 dataset_name TEXT NOT NULL, source_url TEXT NOT NULL, attack_category TEXT NOT NULL,
 observed_at TEXT, source_ip TEXT, destination_ip TEXT, protocol TEXT,
 flow_duration INTEGER, packets INTEGER, bytes INTEGER, imported_at TEXT
);
CREATE TABLE source_sync_state (
 source_name TEXT PRIMARY KEY, last_success_at TEXT NOT NULL, cursor_value TEXT,
 records_imported INTEGER NOT NULL DEFAULT 0
);
"""


class CloudSentinelTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.database = self.root / "test.sqlite3"
        with sqlite3.connect(self.database) as conn:
            conn.executescript(SQLITE_SCHEMA)
            conn.execute(
                "INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",
                ("admin", generate_password_hash("Secure-admin-password-1"), "admin"),
            )
            conn.execute(
                "INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",
                ("analyst", generate_password_hash("Secure-analyst-password-1"), "analyst"),
            )
        conn.close()
        self.app = create_app(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": False,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": str(self.database),
                "UPLOAD_FOLDER": str(self.root / "evidence"),
                "MAX_CONTENT_LENGTH": 10 * 1024 * 1024,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.database)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def login(self, username="analyst", password="Secure-analyst-password-1"):
        return self.client.post("/login", data={"username": username, "password": password})

    def create_incident(self, **overrides):
        values = {
            "title": "Suspicious API access",
            "description": "Unexpected calls from a new source IP.",
            "category": "API Abuse",
            "severity": "High",
            "status": "Open",
            "assigned_to": "",
            "affected_resource": "production-api",
            "detection_at": "2026-10-22T16:30",
            "resolution_notes": "",
        }
        values.update(overrides)
        return self.client.post("/incidents/new", data=values)

    def test_startup_configuration_and_route_registration(self):
        self.assertEqual(self.app.config["MAX_CONTENT_LENGTH"], 10 * 1024 * 1024)
        self.assertIn("dashboard", self.app.view_functions)
        self.assertEqual(self.client.get("/login").status_code, 200)

    def test_database_health_checks_schema_and_login_query(self):
        response = self.client.get("/health/database")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_mysql_database_health_consumes_table_check_results(self):
        class UnreadResultCursor:
            def __init__(self):
                self.has_unread_result = False

            def execute(self, sql, params=()):
                if self.has_unread_result:
                    raise mysql.connector.InternalError("Unread result found")
                self.has_unread_result = True

            def fetchall(self):
                self.has_unread_result = False
                return []

            def fetchone(self):
                self.has_unread_result = False
                return None

            def close(self):
                pass

        class FakeConnection:
            def __init__(self):
                self.mysql_cursor = UnreadResultCursor()

            def cursor(self, dictionary=False):
                return self.mysql_cursor

            def commit(self):
                pass

            def rollback(self):
                pass

            def close(self):
                pass

        mysql_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": None,
                "DB_HOST": "127.0.0.1",
                "DB_PORT": 3306,
                "DB_NAME": "cloudsentinel",
                "DB_USER": "cloudsentinel",
                "DB_PASSWORD": "test-only-password",
                "UPLOAD_FOLDER": str(self.root / "mysql-health-evidence"),
            }
        )
        with patch("app.mysql.connector.connect", return_value=FakeConnection()):
            response = mysql_app.test_client().get("/health/database")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_database_health_rejects_missing_schema(self):
        app_without_schema = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": str(self.root / "empty.sqlite3"),
                "UPLOAD_FOLDER": str(self.root / "empty-evidence"),
            }
        )
        with self.assertLogs("app", level="ERROR"):
            response = app_without_schema.test_client().get("/health/database")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json, {"status": "unavailable"})

    def test_database_health_logs_sanitized_connection_errors(self):
        app_without_database = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": None,
                "UPLOAD_FOLDER": str(self.root / "unavailable-evidence"),
            }
        )
        error = mysql.connector.Error(msg="password=must-not-appear")
        with patch("app.mysql.connector.connect", side_effect=error):
            with self.assertLogs("app", level="ERROR") as captured:
                response = app_without_database.test_client().get("/health/database")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json, {"status": "unavailable"})
        self.assertIn("operation=health check", captured.output[0])
        self.assertNotIn("must-not-appear", captured.output[0])

    def test_mysql_connection_uses_application_database_configuration(self):
        configured_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-only-secret",
                "DATABASE": None,
                "DB_HOST": "db.example.test",
                "DB_PORT": 3307,
                "DB_NAME": "configured_db",
                "DB_USER": "configured_user",
                "DB_PASSWORD": "test-only-password",
                "UPLOAD_FOLDER": str(self.root / "configured-evidence"),
            }
        )
        with patch("app.mysql.connector.connect") as connect:
            connect.side_effect = mysql.connector.Error()
            response = configured_app.test_client().get("/health/database")
        self.assertEqual(response.status_code, 503)
        connect.assert_called_once_with(
            host="db.example.test",
            port=3307,
            user="configured_user",
            password="test-only-password",
            database="configured_db",
            charset="utf8mb4",
            use_unicode=True,
            connection_timeout=5,
        )

    def test_login_success_failure_logout_and_audit(self):
        failed = self.login("analyst", "incorrect-password")
        self.assertEqual(failed.status_code, 200)
        self.assertIn(b"Invalid username/password", failed.data)
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/dashboard"))
        self.assertEqual(self.client.post("/logout").status_code, 302)
        with self.db() as conn:
            actions = [row[0] for row in conn.execute("SELECT action FROM audit_logs ORDER BY id")]
        self.assertEqual(actions, ["LOGIN", "LOGOUT"])

    def test_anonymous_access_is_restricted(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(self.client.get("/incidents").status_code, 302)
        self.assertEqual(self.client.get("/audit").status_code, 302)

    def test_admin_and_analyst_permissions(self):
        self.login()
        self.assertEqual(self.client.get("/users").status_code, 403)
        self.assertEqual(self.client.get("/audit").status_code, 403)
        self.client.post("/logout")
        self.login("admin", "Secure-admin-password-1")
        self.assertEqual(self.client.get("/users").status_code, 200)
        self.assertEqual(self.client.get("/audit").status_code, 200)

    def test_incident_create_validation_and_dashboard_counts(self):
        self.login()
        response = self.create_incident()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.create_incident(severity="Urgent").status_code, 400)
        self.assertEqual(self.create_incident(title="").status_code, 400)
        page = self.client.get("/dashboard").data
        self.assertIn(b"1</div>", page)
        with self.db() as conn:
            incident = conn.execute(
                "SELECT title, status, severity, detection_at, affected_resource FROM incidents"
            ).fetchone()
        self.assertEqual(incident, ("Suspicious API access", "Open", "High", "2026-10-22 16:30:00", "production-api"))

    def test_dashboard_separates_public_vulnerabilities_from_incidents(self):
        with self.db() as conn:
            conn.execute(
                """INSERT INTO vulnerabilities
                   (cve_id,source_name,source_identifier,source_url,description,published_at,
                    severity_score,severity_label,is_kev,kev_source_name,imported_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "CVE-2026-11111", "NVD", "CVE-2026-11111",
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-11111",
                    "Public source record", "2026-10-01 00:00:00",
                    9.8, "CRITICAL", 1, "CISA KEV", "2026-10-23 00:00:00",
                ),
            )
            conn.execute(
                """INSERT INTO vulnerabilities
                   (cve_id,source_name,source_identifier,source_url,description,published_at,
                    imported_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    "CVE-2026-22222", "NVD", "CVE-2026-22222",
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-22222",
                    "Severity omitted by source", "2026-09-01 00:00:00",
                    "2026-10-23 00:00:00",
                ),
            )
        self.create_incident()
        self.login()
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Imported vulnerabilities", response.data)
        self.assertIn(b"CISA KEV entries", response.data)
        self.assertIn(b"Unknown / not provided", response.data)
        self.assertIn(b"Operational incidents", response.data)
        self.assertIn(b"CVE-2026-11111", response.data)
        self.assertNotIn(b"Vulnerability imported as an operational incident", response.data)

    def test_admin_can_manually_sync_but_analyst_cannot(self):
        self.login()
        self.assertEqual(self.client.post("/admin/data-sync").status_code, 403)
        self.client.post("/logout")
        self.login("admin", "Secure-admin-password-1")
        with patch("app.sync_public_sources", return_value={"cisa_kev": 1}) as sync:
            response = self.client.post("/admin/data-sync")
        self.assertEqual(response.status_code, 302)
        sync.assert_called_once()
        with self.db() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT action FROM audit_logs WHERE action='PUBLIC_DATA_SYNC'"
                ).fetchone()[0],
                "PUBLIC_DATA_SYNC",
            )

    def test_incident_list_filters_and_assignment(self):
        self.login()
        self.create_incident(assigned_to="2", category="API Abuse", severity="High")
        self.create_incident(title="Failed console login", category="Suspicious Login", severity="Critical")
        filtered = self.client.get("/incidents?severity=High&category=API+Abuse&assignee=2")
        self.assertIn(b"Suspicious API access", filtered.data)
        self.assertNotIn(b"Failed console login", filtered.data)
        self.assertEqual(self.client.get("/incidents?status=Resolved").status_code, 200)
        self.assertEqual(self.client.get("/incidents?q=console").status_code, 200)

    def test_incident_update_records_status_and_assignment_changes(self):
        self.login()
        self.create_incident()
        response = self.client.post(
            "/incidents/1/update",
            data={
                "title": "Suspicious API access",
                "description": "Unexpected calls from a new source IP.",
                "category": "API Abuse",
                "severity": "Critical",
                "status": "In Progress",
                "assigned_to": "2",
                "affected_resource": "production-api",
                "detection_at": "2026-10-22T16:30",
                "resolution_notes": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        with self.db() as conn:
            self.assertEqual(conn.execute("SELECT status, severity, assigned_to FROM incidents WHERE id=1").fetchone(), ("In Progress", "Critical", 2))
            actions = [row[0] for row in conn.execute("SELECT action FROM audit_logs WHERE entity_type='incident'")]
        self.assertIn("STATUS_CHANGED", actions)
        self.assertIn("INCIDENT_ASSIGNED", actions)

    def test_incident_details_and_admin_delete_keep_audit_and_remove_evidence(self):
        self.login()
        self.create_incident()
        self.client.post(
            "/incidents/1/evidence",
            data={"evidence": (io.BytesIO(b"keep audit, delete file"), "proof.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(self.client.get("/incidents/1").status_code, 200)
        self.assertEqual(self.client.post("/incidents/1/delete").status_code, 403)
        with self.db() as conn:
            key = conn.execute("SELECT storage_key FROM evidence WHERE incident_id=1").fetchone()[0]
        stored = self.root / "evidence" / key
        self.assertTrue(stored.exists())
        self.client.post("/logout")
        self.login("admin", "Secure-admin-password-1")
        self.assertEqual(self.client.get("/incidents/1").status_code, 200)
        deleted = self.client.post(
            "/incidents/1/delete",
        )
        self.assertEqual(deleted.status_code, 302)
        self.assertFalse(stored.exists())
        with self.db() as conn:
            self.assertIsNone(conn.execute("SELECT id FROM incidents WHERE id=1").fetchone())
            self.assertEqual(
                conn.execute("SELECT action FROM audit_logs WHERE action='INCIDENT_DELETED'").fetchone()[0],
                "INCIDENT_DELETED",
            )

    def test_evidence_upload_download_validation_and_anonymous_restriction(self):
        self.login()
        self.create_incident()
        bad = self.client.post(
            "/incidents/1/evidence",
            data={"evidence": (io.BytesIO(b"not allowed"), "payload.exe")},
            content_type="multipart/form-data",
        )
        self.assertEqual(bad.status_code, 302)
        good = self.client.post(
            "/incidents/1/evidence",
            data={"evidence": (io.BytesIO(b"incident evidence"), "../../evidence.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(good.status_code, 302)
        with self.db() as conn:
            row = conn.execute("SELECT id, original_name, size_bytes FROM evidence").fetchone()
        self.assertEqual(row[1:], ("evidence.log", len(b"incident evidence")))
        download = self.client.get(f"/evidence/{row[0]}")
        self.assertEqual(download.data, b"incident evidence")
        download.close()
        with self.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action='EVIDENCE_DOWNLOADED'").fetchone()[0]
        self.assertEqual(count, 1)
        self.client.post("/logout")
        self.assertEqual(self.client.get(f"/evidence/{row[0]}").status_code, 302)

    def test_evidence_request_size_limit(self):
        self.login()
        self.create_incident()
        response = self.client.post(
            "/incidents/1/evidence",
            data={"evidence": (io.BytesIO(b"x" * (10 * 1024 * 1024 + 1)), "large.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)
        with self.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)

    def test_user_management_validation_role_change_and_last_admin_guard(self):
        self.login("admin", "Secure-admin-password-1")
        self.assertEqual(self.client.post("/users", data={"username": "new.user", "password": "Valid-password-123", "role": "analyst"}).status_code, 302)
        self.assertEqual(self.client.post("/users", data={"username": "bad", "password": "short", "role": "admin"}).status_code, 200)
        self.assertEqual(self.client.post("/users/1/update", data={"role": "analyst", "is_active": "1"}).status_code, 302)
        self.assertEqual(self.client.post("/users/2/update", data={"role": "admin", "is_active": "0"}).status_code, 302)
        with self.db() as conn:
            account = conn.execute("SELECT role, is_active FROM users WHERE username='new.user'").fetchone()
            active_admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0]
        self.assertEqual(account, ("analyst", 1))
        self.assertGreaterEqual(active_admins, 1)

    def test_audit_view_is_admin_only(self):
        self.login()
        self.assertEqual(self.client.get("/audit").status_code, 403)
        self.client.post("/logout")
        self.login("admin", "Secure-admin-password-1")
        self.assertEqual(self.client.get("/audit").status_code, 200)

    def test_csrf_protection_rejects_state_change_without_token(self):
        csrf_app = create_app(
            {
                "TESTING": True,
                "WTF_CSRF_ENABLED": True,
                "SECRET_KEY": "test-only-csrf-secret",
                "DATABASE": str(self.database),
                "UPLOAD_FOLDER": str(self.root / "csrf-evidence"),
            }
        )
        response = csrf_app.test_client().post("/login", data={"username": "admin", "password": "anything"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
