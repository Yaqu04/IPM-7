"""NVD CVE API 2.0 -> cve_facts (NVD-Felder) und cve_affected (data_source 'nvd').
fetch_state: last_modified (Ende des zuletzt abgefragten Fensters).
source.config: initial_days (Standard 7), page_size (Standard 2000)."""
import re
import time
from datetime import datetime, timedelta, timezone

from .. import facts
from ..config import settings
from ..models import FetchResult

DEFAULT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW = timedelta(days=120)   # NVD erlaubt hoechstens 120 Tage je Abfrage
_SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CVSS_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
              ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))
_CPE_SPLIT = re.compile(r"(?<!\\):")


def _cvss(metrics: dict) -> dict:
    for key, default_version in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        if data.get("baseScore") is None:
            continue
        severity = (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
        return {"cvss_score": data["baseScore"], "cvss_vector": data.get("vectorString"),
                "cvss_version": data.get("version") or default_version,
                "cvss_severity": severity if severity in _SEVERITIES else None}
    return {"cvss_score": None, "cvss_vector": None, "cvss_version": None, "cvss_severity": None}


def _affected(configurations: list[dict]) -> list[dict]:
    rows = []

    def walk(nodes):
        for node in nodes:
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = _CPE_SPLIT.split(m.get("criteria", ""))
                if len(parts) < 6:
                    continue
                version = parts[5]
                rows.append({
                    "cpe": m["criteria"],
                    "vendor": parts[3].lower(),
                    "product": parts[4].lower(),
                    "version_exact": None if version in ("*", "-") else version,
                    "version_start_including": m.get("versionStartIncluding"),
                    "version_start_excluding": m.get("versionStartExcluding"),
                    "version_end_including": m.get("versionEndIncluding"),
                    "version_end_excluding": m.get("versionEndExcluding"),
                })
            walk(node.get("children", []))

    for conf in configurations:
        walk(conf.get("nodes", []))
    return rows


def parse_cve(vuln: dict) -> tuple[dict, list[dict]]:
    """Eine Eintragung der API -> (cve_facts-Felder, cve_affected-Zeilen)."""
    cve = vuln["cve"]
    descriptions = cve.get("descriptions") or []
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else None)
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if re.fullmatch(r"CWE-\d+", d.get("value", ""))})
    rec = {
        "cve_id": cve["id"].upper(),
        "description": desc,
        "nvd_status": cve.get("vulnStatus"),
        "published_at": facts.parse_ts(cve.get("published")),
        "nvd_modified_at": facts.parse_ts(cve.get("lastModified")),
        "cwe_ids": cwes,
        **_cvss(cve.get("metrics") or {}),
    }
    return rec, _affected(cve.get("configurations") or [])


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def fetch(source: dict, state: dict | None, http, conn) -> FetchResult:
    cfg = source.get("config") or {}
    end = datetime.now(timezone.utc)
    last = facts.parse_ts((state or {}).get("last_modified"))
    start = last or end - timedelta(days=int(cfg.get("initial_days", 7)))
    start = max(start, end - MAX_WINDOW)
    page_size = int(cfg.get("page_size", 2000))
    key = settings().nvd_api_key
    headers = {"apiKey": key} if key else {}
    pause = 0.7 if key else 6.5   # NVD: 50 Anfragen/30 s mit, 5/30 s ohne Schluessel

    index, total, changed = 0, None, 0
    while total is None or index < total:
        if index:
            time.sleep(pause)
        resp = http.get(source["url"] or DEFAULT_URL, headers=headers, params={
            "lastModStartDate": _fmt(start), "lastModEndDate": _fmt(end),
            "resultsPerPage": page_size, "startIndex": index})
        data = resp.json()
        total = int(data.get("totalResults", 0))
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for v in vulns:
            rec, affected = parse_cve(v)
            facts.upsert_nvd(conn, rec)
            facts.replace_affected(conn, rec["cve_id"], "nvd", affected)
            changed += 1
        index += len(vulns)
    return FetchResult(state={"last_modified": _fmt(end)}, seen=total or 0, changed=changed)
