import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
CIC_IDS_URL = "https://www.unb.ca/cic/datasets/ids-2017.html"
MAX_CISA_BYTES = 20 * 1024 * 1024
MAX_ATTACK_BYTES = 100 * 1024 * 1024
NVD_PAGE_SIZE = 2000


class DataImportError(Exception):
    def __init__(self, source, message):
        super().__init__(message)
        self.source = source


def timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def date_value(value):
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return None


def _json_bytes(response, source, max_bytes):
    body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise DataImportError(source, "The source response exceeded the configured size limit.")
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataImportError(source, "The source returned invalid JSON.") from exc


class JsonHttpClient:
    def __init__(self, timeout=30, retries=4, user_agent="CloudSentinel/1.0"):
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent

    def get_json(self, url, source, max_bytes, headers=None):
        request_headers = {"User-Agent": self.user_agent, "Accept": "application/json"}
        if headers:
            request_headers.update(headers)
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(url, headers=request_headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    try:
                        return _json_bytes(response, source, max_bytes)
                    except DataImportError as exc:
                        if "invalid JSON" not in str(exc) or attempt == self.retries:
                            raise
                        delay = _retry_delay(None, attempt)
                        time.sleep(delay)
                        continue
            except urllib.error.HTTPError as exc:
                if exc.code == 304:
                    return None
                retry_after = exc.headers.get("Retry-After")
                retryable = exc.code == 429 or 500 <= exc.code < 600
                if not retryable or attempt == self.retries:
                    raise DataImportError(
                        source, f"The source returned HTTP {exc.code}."
                    ) from exc
                delay = _retry_delay(retry_after, attempt)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt == self.retries:
                    raise DataImportError(
                        source, "The source request failed after retries."
                    ) from exc
                delay = _retry_delay(None, attempt)
            time.sleep(delay)
        raise DataImportError(source, "The source request failed.")


def _retry_delay(retry_after, attempt):
    if retry_after:
        try:
            return min(60.0, max(0.0, float(retry_after)))
        except ValueError:
            pass
    return min(30.0, 2**attempt)


def parse_cisa_record(record):
    cve_id = record.get("cveID")
    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        return None
    products = " ".join(
        part for part in (record.get("vendorProject"), record.get("product")) if part
    )
    return {
        "cve_id": cve_id,
        "source_name": "CISA KEV",
        "source_identifier": cve_id,
        "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}",
        "description": record.get("shortDescription") or record.get("vulnerabilityName"),
        "kev_date_added": date_value(record.get("dateAdded")),
        "kev_due_date": date_value(record.get("dueDate")),
        "kev_required_action": record.get("requiredAction"),
        "kev_ransomware_use": record.get("knownRansomwareCampaignUse"),
        "affected_products": products or None,
    }


def _nvd_severity(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        label = data.get("baseSeverity") or entries[0].get("baseSeverity")
        if score is not None or label:
            return score, label
    return None, None


def _nvd_products(cve):
    products = set()

    def visit(nodes):
        for node in nodes or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if (
                    match.get("vulnerable", True)
                    and len(parts) > 5
                    and parts[2] == "a"
                    and parts[3] != "*"
                    and parts[4] != "*"
                ):
                    products.add(f"{parts[3]} {parts[4]}".replace("_", " "))
            visit(node.get("children"))

    for configuration in cve.get("configurations") or []:
        visit(configuration.get("nodes"))
    return "; ".join(sorted(products)[:8]) or None


def parse_nvd_record(item):
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        return None
    description = next(
        (
            entry.get("value")
            for entry in cve.get("descriptions") or []
            if entry.get("lang") == "en" and entry.get("value")
        ),
        None,
    )
    score, severity = _nvd_severity(cve)
    return {
        "cve_id": cve_id,
        "source_name": "NVD",
        "source_identifier": cve_id,
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "description": description,
        "published_at": timestamp(cve.get("published")),
        "modified_at": timestamp(cve.get("lastModified")),
        "severity_score": score,
        "severity_label": severity,
        "affected_products": _nvd_products(cve),
    }


def _is_sqlite(connection):
    return isinstance(connection, sqlite3.Connection)


def upsert_kev_records(connection, records):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    values = [
        (
            item["cve_id"],
            item["source_name"],
            item["source_identifier"],
            item["source_url"],
            item.get("description"),
            item.get("kev_date_added"),
            item.get("kev_due_date"),
            item.get("kev_required_action"),
            item.get("kev_ransomware_use"),
            item.get("affected_products"),
            now,
        )
        for item in records
        if item
    ]
    if not values:
        return 0
    if _is_sqlite(connection):
        sql = """INSERT INTO vulnerabilities
            (cve_id, source_name, source_identifier, source_url, description,
             kev_date_added, kev_due_date, kev_required_action, kev_ransomware_use,
             affected_products, is_kev, kev_source_name, imported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'CISA KEV', ?)
            ON CONFLICT(cve_id) DO UPDATE SET
             is_kev=1, kev_source_name='CISA KEV',
             kev_source_identifier=excluded.source_identifier,
             kev_source_url=excluded.source_url,
             kev_date_added=excluded.kev_date_added, kev_due_date=excluded.kev_due_date,
             kev_required_action=excluded.kev_required_action,
             kev_ransomware_use=excluded.kev_ransomware_use,
             description=COALESCE(vulnerabilities.description, excluded.description),
             affected_products=COALESCE(vulnerabilities.affected_products, excluded.affected_products),
             imported_at=excluded.imported_at"""
    else:
        sql = """INSERT INTO vulnerabilities
            (cve_id, source_name, source_identifier, source_url, description,
             kev_date_added, kev_due_date, kev_required_action, kev_ransomware_use,
             affected_products, is_kev, kev_source_name, imported_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 'CISA KEV', %s)
            ON DUPLICATE KEY UPDATE
             is_kev=1, kev_source_name='CISA KEV',
             kev_source_identifier=VALUES(source_identifier),
             kev_source_url=VALUES(source_url),
             kev_date_added=VALUES(kev_date_added), kev_due_date=VALUES(kev_due_date),
             kev_required_action=VALUES(kev_required_action),
             kev_ransomware_use=VALUES(kev_ransomware_use),
             description=COALESCE(description, VALUES(description)),
             affected_products=COALESCE(affected_products, VALUES(affected_products)),
             imported_at=VALUES(imported_at)"""
    cursor = connection.cursor()
    try:
        cursor.executemany(sql, values)
        return len(values)
    finally:
        cursor.close()


def upsert_nvd_records(connection, records):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    values = [
        (
            item["cve_id"],
            item["source_name"],
            item["source_identifier"],
            item["source_url"],
            item.get("description"),
            item.get("published_at"),
            item.get("modified_at"),
            item.get("severity_score"),
            item.get("severity_label"),
            item.get("affected_products"),
            now,
        )
        for item in records
        if item
    ]
    if not values:
        return 0
    if _is_sqlite(connection):
        sql = """INSERT INTO vulnerabilities
            (cve_id, source_name, source_identifier, source_url, description,
             published_at, modified_at, severity_score, severity_label,
             affected_products, imported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
             source_name='NVD', source_identifier=excluded.source_identifier,
             source_url=excluded.source_url,
             description=COALESCE(excluded.description, vulnerabilities.description),
             published_at=COALESCE(excluded.published_at, vulnerabilities.published_at),
             modified_at=COALESCE(excluded.modified_at, vulnerabilities.modified_at),
             severity_score=COALESCE(excluded.severity_score, vulnerabilities.severity_score),
             severity_label=COALESCE(excluded.severity_label, vulnerabilities.severity_label),
             affected_products=COALESCE(excluded.affected_products, vulnerabilities.affected_products),
             imported_at=excluded.imported_at"""
    else:
        sql = """INSERT INTO vulnerabilities
            (cve_id, source_name, source_identifier, source_url, description,
             published_at, modified_at, severity_score, severity_label,
             affected_products, imported_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
             source_name='NVD', source_identifier=VALUES(source_identifier),
             source_url=VALUES(source_url),
             description=COALESCE(VALUES(description), description),
             published_at=COALESCE(VALUES(published_at), published_at),
             modified_at=COALESCE(VALUES(modified_at), modified_at),
             severity_score=COALESCE(VALUES(severity_score), severity_score),
             severity_label=COALESCE(VALUES(severity_label), severity_label),
             affected_products=COALESCE(VALUES(affected_products), affected_products),
             imported_at=VALUES(imported_at)"""
    cursor = connection.cursor()
    try:
        cursor.executemany(sql, values)
        return len(values)
    finally:
        cursor.close()


def upsert_attack_objects(connection, objects):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    values = [
        (
            item["stix_id"],
            item["external_id"],
            item["object_type"],
            item["name"],
            item.get("description"),
            item.get("tactic_shortname"),
            "MITRE ATT&CK",
            item["stix_id"],
            item["source_url"],
            item.get("published_at"),
            item.get("modified_at"),
            now,
        )
        for item in objects
    ]
    if not values:
        return 0
    if _is_sqlite(connection):
        sql = """INSERT INTO attack_objects
            (stix_id, external_id, object_type, name, description, tactic_shortname,
             source_name, source_identifier, source_url, published_at, modified_at, imported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stix_id) DO UPDATE SET
             external_id=excluded.external_id, object_type=excluded.object_type,
             name=excluded.name, description=excluded.description,
             tactic_shortname=excluded.tactic_shortname, source_url=excluded.source_url,
             published_at=excluded.published_at, modified_at=excluded.modified_at,
             imported_at=excluded.imported_at"""
    else:
        sql = """INSERT INTO attack_objects
            (stix_id, external_id, object_type, name, description, tactic_shortname,
             source_name, source_identifier, source_url, published_at, modified_at, imported_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
             external_id=VALUES(external_id), object_type=VALUES(object_type),
             name=VALUES(name), description=VALUES(description),
             tactic_shortname=VALUES(tactic_shortname), source_url=VALUES(source_url),
             published_at=VALUES(published_at), modified_at=VALUES(modified_at),
             imported_at=VALUES(imported_at)"""
    cursor = connection.cursor()
    try:
        cursor.executemany(sql, values)
        return len(values)
    finally:
        cursor.close()


def _save_sync_state(connection, source, cursor_value, count):
    synced_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if _is_sqlite(connection):
        sql = """INSERT INTO source_sync_state
            (source_name, last_success_at, cursor_value, records_imported)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source_name) DO UPDATE SET
             last_success_at=excluded.last_success_at, cursor_value=excluded.cursor_value,
             records_imported=excluded.records_imported"""
    else:
        sql = """INSERT INTO source_sync_state
            (source_name, last_success_at, cursor_value, records_imported)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE last_success_at=VALUES(last_success_at),
             cursor_value=VALUES(cursor_value), records_imported=VALUES(records_imported)"""
    cursor = connection.cursor()
    try:
        cursor.execute(sql, (source, synced_at, cursor_value, count))
    finally:
        cursor.close()


def _load_nvd_cursor(connection):
    cursor = connection.cursor()
    try:
        marker = "?" if _is_sqlite(connection) else "%s"
        cursor.execute(
            f"SELECT cursor_value FROM source_sync_state WHERE source_name={marker}",
            ("nvd_cve",),
        )
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        cursor.close()


def _nvd_datetime(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def sync_cisa(connection, client):
    payload = client.get_json(CISA_KEV_URL, "cisa_kev", MAX_CISA_BYTES)
    records = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise DataImportError("cisa_kev", "The CISA feed did not contain a vulnerabilities list.")
    count = upsert_kev_records(connection, [parse_cisa_record(item) for item in records])
    _save_sync_state(connection, "cisa_kev", None, count)
    connection.commit()
    return count


def sync_nvd(connection, client, api_key=None, lookback_days=7, since=None):
    if not 1 <= lookback_days <= 120:
        raise ValueError("NVD lookback must be between 1 and 120 days.")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    saved_cursor = _load_nvd_cursor(connection)
    if since:
        start = _nvd_datetime(since)
    elif saved_cursor:
        start = _nvd_datetime(saved_cursor) - timedelta(minutes=2)
    else:
        start = now - timedelta(days=lookback_days)
    if start >= now:
        start = now - timedelta(minutes=1)
    if now - start > timedelta(days=120):
        raise ValueError("NVD modified-date windows cannot exceed 120 days; choose a more recent --nvd-since date.")
    query_base = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": NVD_PAGE_SIZE,
    }
    headers = {"apiKey": api_key} if api_key else None
    delay = 0.65 if api_key else 6.1
    count = 0
    start_index = 0
    while True:
        query = dict(query_base, startIndex=start_index)
        url = NVD_CVE_URL + "?" + urllib.parse.urlencode(query)
        payload = client.get_json(url, "nvd_cve", 20 * 1024 * 1024, headers=headers)
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise DataImportError("nvd_cve", "NVD returned an invalid vulnerabilities page.")
        items = payload["vulnerabilities"]
        count += upsert_nvd_records(
            connection, [parse_nvd_record(item) for item in items]
        )
        connection.commit()
        total = payload.get("totalResults")
        if not items or not isinstance(total, int) or start_index + len(items) >= total:
            break
        start_index += len(items)
        time.sleep(delay)
    _save_sync_state(connection, "nvd_cve", now.strftime("%Y-%m-%d %H:%M:%S"), count)
    connection.commit()
    return count


def _attack_objects(bundle):
    objects = []
    for item in bundle.get("objects", []) if isinstance(bundle, dict) else []:
        item_type = item.get("type")
        if item_type not in {"x-mitre-tactic", "attack-pattern"} or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        domains = item.get("x_mitre_domains") or []
        if domains and "enterprise-attack" not in domains:
            continue
        external_id = next(
            (
                reference.get("external_id")
                for reference in item.get("external_references") or []
                if reference.get("source_name") == "mitre-attack"
                and reference.get("external_id")
            ),
            None,
        )
        if not item.get("id") or not external_id or not item.get("name"):
            continue
        tactic_shortname = item.get("x_mitre_shortname")
        if item_type == "attack-pattern":
            tactic_shortname = next(
                (
                    phase.get("phase_name")
                    for phase in item.get("kill_chain_phases") or []
                    if phase.get("kill_chain_name") == "mitre-attack"
                ),
                None,
            )
        source_url = (
            f"https://attack.mitre.org/tactics/{external_id}/"
            if item_type == "x-mitre-tactic"
            else f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}/"
        )
        objects.append(
            {
                "stix_id": item["id"],
                "external_id": external_id,
                "object_type": "tactic" if item_type == "x-mitre-tactic" else "technique",
                "name": item["name"],
                "description": item.get("description"),
                "tactic_shortname": tactic_shortname,
                "source_url": source_url,
                "published_at": timestamp(item.get("created")),
                "modified_at": timestamp(item.get("modified")),
            }
        )
    return objects


def _download_attack(client, cache_path):
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        ATTACK_URL,
        headers={"User-Agent": client.user_agent, "Accept": "application/json"},
    )
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_ATTACK_BYTES:
                raise DataImportError("mitre_attack", "The ATT&CK feed exceeds the size limit.")
            total = 0
            with temporary.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ATTACK_BYTES:
                        raise DataImportError("mitre_attack", "The ATT&CK feed exceeds the size limit.")
                    output.write(chunk)
        temporary.replace(path)
        return total
    except DataImportError:
        temporary.unlink(missing_ok=True)
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        temporary.unlink(missing_ok=True)
        raise DataImportError("mitre_attack", "The ATT&CK feed download failed.") from exc


def sync_attack(connection, client, cache_path):
    size = _download_attack(client, cache_path)
    try:
        with Path(cache_path).open("r", encoding="utf-8") as source:
            bundle = json.load(source)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DataImportError("mitre_attack", "The downloaded ATT&CK data was invalid.") from exc
    objects = _attack_objects(bundle)
    count = upsert_attack_objects(connection, objects)
    _save_sync_state(connection, "mitre_attack", None, count)
    connection.commit()
    return count, size


def sync_public_sources(
    connection,
    sources=("cisa", "nvd", "attack"),
    api_key=None,
    nvd_lookback_days=7,
    nvd_since=None,
    attack_cache_path=None,
    client=None,
):
    client = client or JsonHttpClient()
    results = {}
    if "cisa" in sources:
        results["cisa_kev"] = sync_cisa(connection, client)
    if "nvd" in sources:
        results["nvd_cve"] = sync_nvd(
            connection, client, api_key, nvd_lookback_days, nvd_since
        )
    if "attack" in sources:
        if not attack_cache_path:
            attack_cache_path = Path(__file__).resolve().parent / "data_cache" / "enterprise-attack.json"
        count, size = sync_attack(connection, client, attack_cache_path)
        results["mitre_attack"] = count
        results["mitre_attack_download_bytes"] = size
    return results


def _header_map(headers):
    return {
        re.sub(r"[^a-z0-9]", "", header.strip().lower()): index
        for index, header in enumerate(headers)
        if header
    }


def _field(row, mapping, *names):
    for name in names:
        index = mapping.get(re.sub(r"[^a-z0-9]", "", name.lower()))
        if index is not None and index < len(row):
            return row[index].strip()
    return ""


def _flow_timestamp(value):
    if not value:
        return None
    normalized = timestamp(value)
    if normalized:
        return normalized
    for pattern in (
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y %I:%M %p",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
    ):
        try:
            return datetime.strptime(value.strip(), pattern).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return None


def _number(value):
    try:
        parsed = int(float(value.replace(",", "").strip()))
        return max(0, parsed)
    except (TypeError, ValueError):
        return None


def import_cic_csv(connection, csv_path):
    path = Path(csv_path)
    if not path.is_file():
        raise DataImportError("cic_ids", "The configured CIC dataset file does not exist.")
    cursor = connection.cursor()
    inserts = 0
    skipped = 0
    source = "cic-ids-2017"
    try:
        with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as input_file:
            reader = csv.reader(input_file)
            try:
                headers = next(reader)
            except StopIteration:
                raise DataImportError("cic_ids", "The CIC dataset file is empty.")
            mapping = _header_map(headers)
            if not any(name in mapping for name in ("label", "class", "attack")):
                raise DataImportError("cic_ids", "The CIC dataset file has no attack label column.")
            rows = []
            for row_number, row in enumerate(reader, start=2):
                label = _field(row, mapping, "Label", "Class", "Attack")
                if not label or label.strip().lower() in {"benign", "normal"}:
                    skipped += 1
                    continue
                normalized = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                identifier = hashlib.sha256(
                    f"{source}:{row_number}:{digest}".encode("ascii")
                ).hexdigest()
                forward_packets = _number(_field(row, mapping, "Total Fwd Packets"))
                backward_packets = _number(_field(row, mapping, "Total Backward Packets"))
                forward_bytes = _number(_field(row, mapping, "Total Length of Fwd Packets"))
                backward_bytes = _number(_field(row, mapping, "Total Length of Bwd Packets"))
                packets = (
                    (forward_packets or 0) + (backward_packets or 0)
                    if forward_packets is not None or backward_packets is not None
                    else None
                )
                byte_count = (
                    (forward_bytes or 0) + (backward_bytes or 0)
                    if forward_bytes is not None or backward_bytes is not None
                    else None
                )
                rows.append(
                    (
                        identifier,
                        source,
                        CIC_IDS_URL,
                        label[:120],
                        _flow_timestamp(_field(row, mapping, "Timestamp", "Flow Start")),
                        _field(row, mapping, "Source IP", "Src IP")[:45] or None,
                        _field(row, mapping, "Destination IP", "Dst IP")[:45] or None,
                        _field(row, mapping, "Protocol")[:32] or None,
                        _number(_field(row, mapping, "Flow Duration")),
                        packets,
                        byte_count,
                        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    )
                )
                if len(rows) >= 500:
                    inserts += _insert_network_rows(connection, rows)
                    connection.commit()
                    rows.clear()
            if rows:
                inserts += _insert_network_rows(connection, rows)
                connection.commit()
    except OSError as exc:
        raise DataImportError("cic_ids", "The CIC dataset file could not be read.") from exc
    finally:
        cursor.close()
    _save_sync_state(connection, "cic_ids", None, inserts)
    connection.commit()
    return {"imported": inserts, "skipped": skipped}


def _insert_network_rows(connection, values):
    if not values:
        return 0
    if _is_sqlite(connection):
        sql = """INSERT INTO network_observations
            (source_identifier, dataset_name, source_url, attack_category, observed_at,
             source_ip, destination_ip, protocol, flow_duration, packets, bytes, imported_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_identifier) DO NOTHING"""
    else:
        sql = """INSERT INTO network_observations
            (source_identifier, dataset_name, source_url, attack_category, observed_at,
             source_ip, destination_ip, protocol, flow_duration, packets, bytes, imported_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE source_identifier=VALUES(source_identifier)"""
    cursor = connection.cursor()
    try:
        cursor.executemany(sql, values)
        return max(0, cursor.rowcount)
    finally:
        cursor.close()


def _connect_from_env():
    load_dotenv(Path(__file__).resolve().with_name(".env"))
    missing = [
        key
        for key in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
        if not os.getenv(key)
    ]
    if missing:
        raise DataImportError("database", "Required database settings are missing from .env.")
    try:
        port = int(os.getenv("DB_PORT", "3306"))
    except ValueError as exc:
        raise DataImportError("database", "DB_PORT is not a valid integer.") from exc
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        port=port,
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        charset="utf8mb4",
        connection_timeout=10,
    )


def main(argv=None):
    load_dotenv(Path(__file__).resolve().with_name(".env"))
    parser = argparse.ArgumentParser(
        description="Import official public cybersecurity sources into separate CloudSentinel tables."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    sync_parser = subparsers.add_parser("sync", help="Synchronize public vulnerability and ATT&CK sources.")
    sync_parser.add_argument(
        "--sources",
        nargs="+",
        choices=("cisa", "nvd", "attack"),
        default=("cisa", "nvd", "attack"),
    )
    sync_parser.add_argument("--nvd-lookback-days", type=int, default=7)
    sync_parser.add_argument(
        "--nvd-since",
        help="Optional UTC modified-date start (ISO-8601); NVD windows are limited to 120 days.",
    )
    cic_parser = subparsers.add_parser(
        "import-cic", help="Import a locally downloaded CIC-IDS2017 CSV file."
    )
    cic_parser.add_argument(
        "--path",
        default=os.getenv("CICIDS_CSV_PATH"),
        help="Local CIC-IDS2017 CSV path (or set CICIDS_CSV_PATH in .env).",
    )
    args = parser.parse_args(argv)
    if args.command == "import-cic" and not args.path:
        parser.error("import-cic requires --path or CICIDS_CSV_PATH.")
    connection = None
    try:
        connection = _connect_from_env()
        if args.command == "sync":
            cache_path = os.getenv(
                "ATTACK_CACHE_PATH",
                str(Path(__file__).resolve().parent / "data_cache" / "enterprise-attack.json"),
            )
            print(
                "Sources: CISA KEV JSON, NVD modified records "
                f"(initial lookback {args.nvd_lookback_days} days), and the complete "
                "MITRE Enterprise ATT&CK STIX catalog. ATT&CK is downloaded to "
                f"{cache_path}; downloads are limited to 100 MiB and report actual size."
            )
            results = sync_public_sources(
                connection,
                args.sources,
                os.getenv("NVD_API_KEY"),
                args.nvd_lookback_days,
                args.nvd_since,
                cache_path,
            )
            for source, count in results.items():
                if source.endswith("_download_bytes"):
                    print(f"{source}={count} bytes")
                else:
                    print(f"{source} records processed={count}")
        else:
            result = import_cic_csv(connection, args.path)
            print(
                f"cic_ids imported={result['imported']}; "
                f"benign or unlabeled rows skipped={result['skipped']}"
            )
        return 0
    except DataImportError as exc:
        print(f"Import failed for {exc.source}: {exc}", file=sys.stderr)
        return 1
    except mysql.connector.Error as exc:
        print(
            "Database operation failed: "
            f"{type(exc).__name__}, errno={getattr(exc, 'errno', 'unknown')}",
            file=sys.stderr,
        )
        return 1
    finally:
        if connection is not None and connection.is_connected():
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
