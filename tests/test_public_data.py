import io
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from import_public_data import (
    DataImportError,
    JsonHttpClient,
    _attack_objects,
    import_cic_csv,
    parse_nvd_record,
    sync_nvd,
    upsert_kev_records,
)
from tests.test_app import SQLITE_SCHEMA


class PublicDataImportTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.executescript(SQLITE_SCHEMA)

    def tearDown(self):
        self.connection.close()

    def test_kev_upsert_is_idempotent_and_preserves_nvd_fields(self):
        record = {
            "cve_id": "CVE-2026-12345",
            "source_name": "CISA KEV",
            "source_identifier": "CVE-2026-12345",
            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "description": "Public source description",
            "kev_date_added": "2026-10-01",
            "kev_due_date": None,
            "kev_required_action": "Apply vendor updates.",
            "kev_ransomware_use": "Unknown",
            "affected_products": "Example Vendor Example Product",
        }
        upsert_kev_records(self.connection, [record])
        upsert_kev_records(self.connection, [record])
        row = self.connection.execute(
            "SELECT COUNT(*), is_kev, kev_source_name FROM vulnerabilities"
        ).fetchone()
        self.assertEqual(row, (1, 1, "CISA KEV"))

    def test_nvd_parser_handles_missing_description_severity_and_dates(self):
        parsed = parse_nvd_record(
            {
                "cve": {
                    "id": "CVE-2026-54321",
                    "descriptions": [{"lang": "fr", "value": "non-English"}],
                    "metrics": {},
                }
            }
        )
        self.assertEqual(parsed["cve_id"], "CVE-2026-54321")
        self.assertIsNone(parsed["description"])
        self.assertIsNone(parsed["severity_score"])
        self.assertIsNone(parsed["published_at"])
        self.assertIsNone(parse_nvd_record({"cve": {"id": "invalid"}}))

    def test_attack_parser_excludes_other_domains_and_revoked_entries(self):
        objects = _attack_objects(
            {
                "objects": [
                    {
                        "id": "attack-pattern--valid",
                        "type": "attack-pattern",
                        "name": "Valid technique",
                        "x_mitre_domains": ["enterprise-attack"],
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1000"}
                        ],
                        "kill_chain_phases": [
                            {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                        ],
                    },
                    {
                        "id": "attack-pattern--mobile",
                        "type": "attack-pattern",
                        "name": "Mobile-only technique",
                        "x_mitre_domains": ["mobile-attack"],
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T2000"}
                        ],
                    },
                    {
                        "id": "attack-pattern--revoked",
                        "type": "attack-pattern",
                        "name": "Revoked technique",
                        "revoked": True,
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T3000"}
                        ],
                    },
                ]
            }
        )
        self.assertEqual(len(objects), 1)
        self.assertEqual(objects[0]["tactic_shortname"], "execution")

    def test_http_client_retries_rate_limit_and_fails_on_bad_response(self):
        class Response:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"ok": true}'

        rate_limit = __import__("urllib.error").error.HTTPError(
            "https://example.test", 429, "rate limited", {"Retry-After": "0"}, None
        )
        with patch("import_public_data.urllib.request.urlopen", side_effect=[rate_limit, Response()]) as get, patch(
            "import_public_data.time.sleep"
        ):
            result = JsonHttpClient(retries=1).get_json(
                "https://example.test", "test-source", 1024
            )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(get.call_count, 2)
        with patch(
            "import_public_data.urllib.request.urlopen",
            side_effect=__import__("urllib.error").error.HTTPError(
                "https://example.test", 404, "not found", {}, None
            ),
        ):
            with self.assertRaises(DataImportError):
                JsonHttpClient(retries=0).get_json(
                    "https://example.test", "test-source", 1024
                )

    def test_http_client_retries_transient_non_json_response(self):
        class Response:
            headers = {}

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return self.body

        with patch(
            "import_public_data.urllib.request.urlopen",
            side_effect=[Response(b""), Response(b'{"ok": true}')],
        ), patch("import_public_data.time.sleep"):
            result = JsonHttpClient(retries=1).get_json(
                "https://example.test", "test-source", 1024
            )
        self.assertEqual(result, {"ok": True})

    def test_nvd_sync_paginates_and_saves_incremental_cursor(self):
        class Client:
            def __init__(self):
                self.indexes = []

            def get_json(self, url, source, max_bytes, headers=None):
                self.assert_source = source
                self.assert_headers = headers
                query = parse_qs(urlparse(url).query)
                index = int(query["startIndex"][0])
                self.indexes.append(index)
                if index == 0:
                    return {
                        "totalResults": 2,
                        "vulnerabilities": [
                            {"cve": {"id": "CVE-2026-11111", "lastModified": "2026-10-22T01:00:00Z"}}
                        ],
                    }
                return {
                    "totalResults": 2,
                    "vulnerabilities": [
                        {"cve": {"id": "CVE-2026-22222", "lastModified": "2026-10-22T02:00:00Z"}}
                    ],
                }

        client = Client()
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with patch("import_public_data.time.sleep") as sleep:
            count = sync_nvd(self.connection, client, since=since)
        self.assertEqual(count, 2)
        self.assertEqual(client.indexes, [0, 1])
        self.assertEqual(client.assert_source, "nvd_cve")
        self.assertIsNone(client.assert_headers)
        self.assertEqual(
            self.connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0],
            2,
        )
        self.assertIsNotNone(
            self.connection.execute(
                "SELECT last_success_at FROM source_sync_state WHERE source_name='nvd_cve'"
            ).fetchone()
        )
        sleep.assert_called_once_with(6.1)

    def test_cic_import_requires_a_real_file_and_prevents_duplicate_rows(self):
        with self.assertRaises(DataImportError):
            import_cic_csv(self.connection, "missing-cic-dataset.csv")
        sample = io.StringIO(
            "Timestamp,Source IP,Destination IP,Protocol,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label\n"
            "7/7/2017 3:30,192.0.2.1,198.51.100.2,6,2,3,100,200,DoS Hulk\n"
            "7/7/2017 3:31,192.0.2.2,198.51.100.2,6,1,1,50,50,BENIGN\n"
        )
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cic.csv"
            path.write_text(sample.getvalue(), encoding="utf-8")
            first = import_cic_csv(self.connection, path)
            second = import_cic_csv(self.connection, path)
        self.assertEqual(first, {"imported": 1, "skipped": 1})
        self.assertEqual(second, {"imported": 0, "skipped": 1})
        row = self.connection.execute(
            "SELECT attack_category, packets, bytes FROM network_observations"
        ).fetchone()
        self.assertEqual(row, ("DoS Hulk", 5, 300))


if __name__ == "__main__":
    unittest.main()
