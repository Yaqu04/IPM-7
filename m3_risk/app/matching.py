"""Abgleich Meldung -> Inventar ueber CVE und NVD-CPE (Wege 1 und 3 im README).

Ablauf je Meldung:
  1. Kandidaten per SQL: cve_affected (NVD) mit gleichem Hersteller/Produkt wie eine aktive Komponente
  2. Versionsvergleich in Python (versions.check_range) je Regel
  3. Je (Komponente, CVE): affected > unknown > not_affected
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .normalize import is_wildcard, parse_cpe23
from .versions import check_range

RANGE_FIELDS = ("version_exact", "version_start_including", "version_start_excluding",
                "version_end_including", "version_end_excluding")

CONFIDENCE = {
    "range": 0.95,          # Version liegt sicher in einem angegebenen Bereich
    "all_versions": 0.85,   # Regel ohne Version und ohne Grenzen: alle Versionen betroffen
    "unknown": 0.60,        # Produkt passt, Version nicht auswertbar
}


@dataclass
class Candidate:
    component_id: int
    asset_id: int
    cve_id: str
    match_method: str
    confidence: float
    version_status: str
    match_details: dict[str, Any]
    dependency_path: list[int] = field(default_factory=list)

    @property
    def match_key(self) -> str:
        return self.cve_id


@dataclass
class MatchResult:
    candidates: dict[tuple[int, str], Candidate]      # (component_id, match_key) -> Treffer
    not_affected: set[tuple[int, str]]                 # Produkt passt, Version sicher nicht betroffen


def _rule(row: dict[str, Any]) -> dict[str, Any]:
    rule = {"source": "nvd", "cpe": row["cpe"]}
    rule.update({f: row[f] for f in RANGE_FIELDS if row[f] is not None})
    return rule


def _exact_from_cpe(row: dict[str, Any]) -> str | None:
    """M1 fuellt version_exact; falls nicht, steht eine feste Version evtl. direkt in der CPE."""
    if row["version_exact"] is not None:
        return row["version_exact"]
    cpe = parse_cpe23(row["cpe"])
    if cpe and not is_wildcard(cpe["version"]):
        return cpe["version"]
    return None


def _component_version(row: dict[str, Any]) -> str | None:
    if row["comp_version"]:
        return row["comp_version"]
    cpe = parse_cpe23(row["comp_cpe"])
    if cpe and not is_wildcard(cpe["version"]):
        return cpe["version"]
    return None


def dependency_path(conn, component_id: int) -> list[int]:
    """Komponenten-IDs von oben (Image) bis zur Komponente selbst."""
    rows = conn.execute("""
        WITH RECURSIVE up(id, parent_component_id, depth) AS (
            SELECT id, parent_component_id, 0 FROM m3.sbom_components WHERE id = %s
            UNION ALL
            SELECT c.id, c.parent_component_id, up.depth + 1
              FROM m3.sbom_components c JOIN up ON c.id = up.parent_component_id
             WHERE up.depth < 20
        )
        SELECT id FROM up ORDER BY depth DESC
    """, (component_id,)).fetchall()
    return [r["id"] for r in rows]


def match_cves(conn, cve_ids: list[str]) -> MatchResult:
    result = MatchResult(candidates={}, not_affected=set())
    if not cve_ids:
        return result
    rows = conn.execute("""
        SELECT ca.cve_id, ca.cpe, ca.vendor, ca.product,
               ca.version_exact, ca.version_start_including, ca.version_start_excluding,
               ca.version_end_including, ca.version_end_excluding,
               c.id AS component_id, c.asset_id, c.version AS comp_version, c.cpe23 AS comp_cpe
          FROM public.cve_affected ca
          JOIN m3.sbom_components c
            ON c.vendor_norm = ca.vendor AND c.product_norm = ca.product AND c.is_active
          JOIN m3.assets a ON a.id = c.asset_id AND a.is_active
         WHERE ca.data_source = 'nvd' AND ca.cve_id = ANY(%s)
         ORDER BY ca.cve_id, c.id, ca.cpe
    """, (cve_ids,)).fetchall()

    grouped: dict[tuple[int, str], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault((row["component_id"], row["cve_id"]), []).append(row)

    for (component_id, cve_id), rules in grouped.items():
        version = _component_version(rules[0])
        evaluated = []
        for r in rules:
            exact = _exact_from_cpe(r)
            status = check_range(version, exact, r["version_start_including"], r["version_start_excluding"],
                                 r["version_end_including"], r["version_end_excluding"])
            all_versions = exact is None and all(r[f] is None for f in RANGE_FIELDS[1:])
            evaluated.append((status, all_versions, r))

        affected = [e for e in evaluated if e[0] == "affected"]
        unknown = [e for e in evaluated if e[0] == "unknown"]
        if affected:
            precise = [e for e in affected if not e[1]]
            chosen = (precise or affected)[0]
            method, version_status = "cpe_version", "affected"
            confidence = CONFIDENCE["all_versions" if chosen[1] else "range"]
            used = [chosen[2]]
        elif unknown:
            method, version_status, confidence = "cpe_product_only", "unknown", CONFIDENCE["unknown"]
            used = [e[2] for e in unknown]
        else:
            result.not_affected.add((component_id, cve_id))
            continue

        result.candidates[(component_id, cve_id)] = Candidate(
            component_id=component_id,
            asset_id=rules[0]["asset_id"],
            cve_id=cve_id,
            match_method=method,
            confidence=confidence,
            version_status=version_status,
            match_details={"component_version": version, "rules": [_rule(r) for r in used],
                           "rules_checked": len(rules)},
        )

    for cand in result.candidates.values():
        cand.dependency_path = dependency_path(conn, cand.component_id)
    return result
