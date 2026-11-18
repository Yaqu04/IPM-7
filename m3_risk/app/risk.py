"""Risiko-Score: regelbasiert, nachrechenbar, ohne KI.

Jeder Faktor liefert einen Wert zwischen 0 und 1 und wird mit seinem Gewicht aus risk_policy.yaml
multipliziert. Fehlende Werte zaehlen 0 und werden in factor_breakdown als "missing" markiert,
damit die Oberflaeche zeigen kann, dass der Score unvollstaendig ist.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

LEVELS = ("critical", "high", "medium", "low", "info")
FACTORS = ("severity", "exploitation", "criticality", "exposure", "trust", "confidence")


@dataclass(frozen=True)
class Policy:
    version: str
    weights: dict[str, float]
    levels: list[tuple[str, float]]
    floors: dict[str, str]
    actions: dict[str, dict[str, Any]]


def load_policy(path: Path) -> Policy:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    weights = {k: float(v) for k, v in raw["weights"].items()}
    if set(weights) != set(FACTORS):
        raise ValueError(f"risk_policy: weights must contain exactly {FACTORS}")
    if abs(sum(weights.values()) - 100) > 1e-6:
        raise ValueError("risk_policy: weights must sum to 100")
    levels = sorted(((l["level"], float(l["min_score"])) for l in raw["levels"]), key=lambda x: -x[1])
    if {l for l, _ in levels} != set(LEVELS):
        raise ValueError(f"risk_policy: levels must be {LEVELS}")
    actions = raw["actions"]
    if set(actions) != set(LEVELS):
        raise ValueError(f"risk_policy: actions must be defined for {LEVELS}")
    floors = raw.get("floors") or {}
    for lvl in floors.values():
        if lvl not in LEVELS:
            raise ValueError(f"risk_policy: unknown floor level {lvl}")
    return Policy(str(raw["version"]), weights, levels, floors, actions)


@dataclass(frozen=True)
class RiskInput:
    cvss_score: float | None
    kev_listed: bool | None
    kev_due_date: date | None
    epss_score: float | None
    asset_criticality: int
    internet_exposed: bool
    trust_score: float | None
    match_confidence: float
    version_status: str          # affected / unknown / not_applicable


@dataclass(frozen=True)
class RiskResult:
    score: float
    risk_level: str
    action_code: str
    deadline_at: datetime | None
    factor_breakdown: dict[str, Any]


def _factor_values(inp: RiskInput) -> dict[str, tuple[float, bool, dict[str, Any]]]:
    """Faktor -> (Wert 0..1, fehlt?, Eingangswerte)."""
    out: dict[str, tuple[float, bool, dict[str, Any]]] = {}
    if inp.cvss_score is None:
        out["severity"] = (0.0, True, {"cvss_score": None})
    else:
        out["severity"] = (min(max(float(inp.cvss_score) / 10, 0), 1), False, {"cvss_score": float(inp.cvss_score)})
    if inp.kev_listed:
        out["exploitation"] = (1.0, False, {"kev_listed": True, "epss_score": inp.epss_score})
    elif inp.epss_score is not None:
        out["exploitation"] = (min(max(float(inp.epss_score), 0), 1), False,
                               {"kev_listed": bool(inp.kev_listed), "epss_score": float(inp.epss_score)})
    else:
        out["exploitation"] = (0.0, True, {"kev_listed": bool(inp.kev_listed), "epss_score": None})
    out["criticality"] = ((inp.asset_criticality - 1) / 4, False, {"asset_criticality": inp.asset_criticality})
    out["exposure"] = (1.0 if inp.internet_exposed else 0.0, False, {"internet_exposed": inp.internet_exposed})
    if inp.trust_score is None:
        out["trust"] = (0.0, True, {"trust_score": None})
    else:
        out["trust"] = (min(max(float(inp.trust_score), 0), 1), False, {"trust_score": float(inp.trust_score)})
    out["confidence"] = (min(max(float(inp.match_confidence), 0), 1), False,
                         {"match_confidence": float(inp.match_confidence)})
    return out


def _deadline(level: str, policy: Policy, now: datetime, kev_due: date | None) -> datetime | None:
    hours = policy.actions[level].get("deadline_hours")
    candidates = []
    if hours is not None:
        candidates.append(now + timedelta(hours=float(hours)))
    if kev_due is not None and level != "info":
        candidates.append(datetime.combine(kev_due, time(23, 59, 59), tzinfo=timezone.utc))
    return min(candidates) if candidates else None


def score(inp: RiskInput, policy: Policy, now: datetime | None = None) -> RiskResult:
    now = now or datetime.now(timezone.utc)
    breakdown: dict[str, Any] = {"policy_version": policy.version, "factors": {}}
    total = 0.0
    for name, (value, missing, inputs) in _factor_values(inp).items():
        points = round(policy.weights[name] * value, 2)
        total += points
        breakdown["factors"][name] = {"weight": policy.weights[name], "value": round(value, 4),
                                      "points": points, "missing": missing, "inputs": inputs}
    total = round(min(max(total, 0), 100), 2)
    level = next(lvl for lvl, min_score in policy.levels if total >= min_score)

    floor = policy.floors.get("kev_exposed_affected")
    breakdown["floor_applied"] = None
    if (floor and inp.kev_listed and inp.internet_exposed and inp.version_status == "affected"
            and LEVELS.index(level) > LEVELS.index(floor)):
        breakdown["floor_applied"] = {"rule": "kev_exposed_affected", "from": level, "to": floor}
        level = floor

    breakdown["missing"] = [n for n, f in breakdown["factors"].items() if f["missing"]]
    return RiskResult(score=total, risk_level=level,
                      action_code=policy.actions[level]["action_code"],
                      deadline_at=_deadline(level, policy, now, inp.kev_due_date),
                      factor_breakdown=breakdown)
