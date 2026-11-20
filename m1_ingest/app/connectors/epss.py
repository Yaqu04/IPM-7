"""EPSS-Tageswerte (CSV, gzip) -> cve_facts.epss_*, nur fuer bekannte CVEs.
fetch_state: etag, last_modified, score_date."""
import csv
import gzip
import io
from datetime import date

from .. import facts
from ..models import FetchResult

DEFAULT_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def parse_csv(content: bytes) -> tuple[date | None, list[tuple[str, float, float]]]:
    """Liefert (Stichtag, [(cve, epss, percentile)])."""
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)
    text = io.StringIO(content.decode("utf-8"))
    score_date = None
    first = text.readline()
    if first.startswith("#"):
        for part in first.lstrip("#").strip().split(","):
            if part.startswith("score_date:"):
                score_date = date.fromisoformat(part.split(":", 1)[1][:10])
    else:
        text.seek(0)
    rows = []
    for rec in csv.DictReader(text):
        try:
            rows.append((rec["cve"].strip().upper(), float(rec["epss"]), float(rec["percentile"])))
        except (KeyError, ValueError):
            continue
    return score_date, rows


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
    score_date, rows = parse_csv(resp.content)
    if not rows:
        raise ValueError("EPSS-Datei ohne Zeilen")
    new_state = {k: v for k, v in (("etag", resp.headers.get("ETag")),
                                   ("last_modified", resp.headers.get("Last-Modified")),
                                   ("score_date", score_date.isoformat() if score_date else None))
                 if v}
    if score_date and new_state.get("score_date") == state.get("score_date"):
        return FetchResult(state=new_state, seen=len(rows))
    known = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM cve_facts").fetchall()}
    return FetchResult(state=new_state, seen=len(rows),
                       changed=facts.update_epss(conn, [r for r in rows if r[0] in known], score_date))
