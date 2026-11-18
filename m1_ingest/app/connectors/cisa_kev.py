"""CISA Known Exploited Vulnerabilities (JSON-Katalog) -> cve_facts.kev_*.
fetch_state: etag, last_modified, catalog_version."""
from datetime import date

from .. import facts
from ..models import FetchResult

DEFAULT_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def parse_catalog(data: dict) -> list[dict]:
    rows = []
    for v in data.get("vulnerabilities", []):
        cve = (v.get("cveID") or "").strip().upper()
        if not cve:
            continue
        rows.append({
            "cve_id": cve,
            "date_added": _date(v.get("dateAdded")),
            "due_date": _date(v.get("dueDate")),
            "action": v.get("requiredAction") or None,
            "ransomware": v.get("knownRansomwareCampaignUse") or None,
        })
    return rows


def fetch(source: dict, state: dict | None, http, conn) -> FetchResult:
    state = state or {}
    headers = {}
    if state.get("etag"):
        headers["If-None-Match"] = state["etag"]
    if state.get("last_modified"):
        headers["If-Modified-Since"] = state["last_modified"]
    resp = http.get(source["url"] or DEFAULT_URL, headers=headers, allow_304=True)
    if resp.status_code == 304:
        return FetchResult(state=state, seen=0)
    data = resp.json()
    version = data.get("catalogVersion")
    new_state = {k: v for k, v in (("etag", resp.headers.get("ETag")),
                                   ("last_modified", resp.headers.get("Last-Modified")),
                                   ("catalog_version", version)) if v}
    rows = parse_catalog(data)
    if not rows:
        raise ValueError("KEV-Katalog ohne Eintraege, Aenderung verworfen")
    if version and version == state.get("catalog_version"):
        return FetchResult(state=new_state, seen=len(rows))
    return FetchResult(state=new_state, seen=len(rows), changed=facts.upsert_kev(conn, rows))
