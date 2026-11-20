"""OSV: betroffene Pakete fuer CVEs, die in raw_items neu aufgetaucht sind -> cve_affected ('osv').
fetch_state: since (fetched_at, ab dem raw_items beruecksichtigt werden).
source.config: batch (Standard 200 CVEs je Lauf)."""
from datetime import datetime, timezone

from .. import facts
from ..httpclient import FetchError
from ..models import FetchResult

DEFAULT_URL = "https://api.osv.dev/v1/vulns"
_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}


def parse_vuln(vuln: dict) -> list[dict]:
    rows = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package") or {}
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        if not eco or not name:
            continue
        base = {"ecosystem": eco, "package_name": name}
        for rng in aff.get("ranges", []):
            if rng.get("type") not in _RANGE_TYPES:
                continue
            start = None
            open_range = False
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    if open_range:
                        rows.append({**base, "version_start_including": start})
                    start = None if ev["introduced"] == "0" else ev["introduced"]
                    open_range = True
                elif "fixed" in ev or "last_affected" in ev:
                    row = {**base, "version_start_including": start}
                    if "fixed" in ev:
                        row["version_end_excluding"] = ev["fixed"]
                    else:
                        row["version_end_including"] = ev["last_affected"]
                    rows.append(row)
                    open_range = False
            if open_range:
                rows.append({**base, "version_start_including": start})
        for v in aff.get("versions", []):
            rows.append({**base, "version_exact": v})
    return rows


def fetch(source: dict, state: dict | None, http, conn) -> FetchResult:
    cfg = source.get("config") or {}
    batch = int(cfg.get("batch", 200))
    started = datetime.now(timezone.utc)
    since = facts.parse_ts((state or {}).get("since")) or datetime.fromtimestamp(0, timezone.utc)
    todo = conn.execute(
        """
        SELECT cve, min(fetched_at) AS first_seen
        FROM (SELECT unnest(cve_ids) AS cve, fetched_at FROM raw_items WHERE fetched_at >= %s) t
        GROUP BY cve ORDER BY first_seen, cve LIMIT %s
        """,
        (since, batch),
    ).fetchall()
    base = (source["url"] or DEFAULT_URL).rstrip("/")
    changed = 0
    for row in todo:
        try:
            resp = http.get(f"{base}/{row['cve']}")
        except FetchError as exc:
            if exc.status == 404:
                continue            # OSV kennt diese CVE (noch) nicht
            raise
        facts.ensure_stub(conn, [row["cve"]])
        if facts.replace_affected(conn, row["cve"], "osv", parse_vuln(resp.json())):
            changed += 1
    next_since = todo[-1]["first_seen"] if len(todo) >= batch else started
    return FetchResult(state={"since": next_since.isoformat()}, seen=len(todo), changed=changed)
