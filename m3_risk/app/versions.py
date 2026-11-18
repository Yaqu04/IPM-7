"""Versionsvergleich fuer den Abgleich mit cve_affected.

Grundsatz: Laesst sich eine Version nicht sicher vergleichen, ist das Ergebnis "unknown",
nie "not_affected". Lieber ein Treffer zu viel (manuell pruefen) als eine uebersehene Luecke.
"""
from __future__ import annotations

import re
from typing import Literal

from packaging.version import InvalidVersion, Version

from .normalize import is_wildcard

Status = Literal["affected", "not_affected", "unknown"]

_TOKEN = re.compile(r"\d+|[a-z]+")

# Nur eindeutige Formate an packaging uebergeben. "1.0.2a" waere dort eine Alpha-Version (< 1.0.2),
# bei OpenSSL & Co. ist es aber ein Patch-Stand (> 1.0.2). Solche Faelle gehen an den Fallback.
_UNAMBIGUOUS = re.compile(r"^v?\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$", re.I)


def _tokens(value: str) -> list[int | str]:
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall(value.lower())]


def compare(a: str | None, b: str | None) -> int | None:
    """-1, 0 oder 1 wie bei cmp(); None, wenn keine sichere Aussage moeglich ist."""
    if is_wildcard(a) or is_wildcard(b):
        return None
    a, b = (re.sub(r"^[vV](?=\d)", "", s.strip()) for s in (a, b))
    if a.lower() == b.lower():
        return 0
    # 1. Standardformat (PEP 440 kennt auch Vorabversionen wie 1.0rc1 < 1.0)
    if _UNAMBIGUOUS.match(a) and _UNAMBIGUOUS.match(b):
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    # 2. Herstellerformate wie "22.7R2.4": Zahlen numerisch, Buchstaben als Text vergleichen
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return None
    for x, y in zip(ta, tb):
        if type(x) is not type(y):
            return None                      # Zahl gegen Buchstabe: unklar
        if x != y:
            return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    longer, rest_sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    rest = longer[min(len(ta), len(tb)):]
    if all(t == 0 for t in rest):
        return 0                             # 7.2 == 7.2.0
    if isinstance(rest[0], int):
        return rest_sign                     # 7.2.1 > 7.2
    return None                              # 1.1.1 vs 1.1.1w: Patch oder Vorabversion? unklar


def check_range(version: str | None,
                exact: str | None = None,
                start_including: str | None = None,
                start_excluding: str | None = None,
                end_including: str | None = None,
                end_excluding: str | None = None) -> Status:
    """Prueft, ob `version` in den Bereich einer cve_affected-Zeile faellt.

    Hat eine Zeile sowohl eine feste Version als auch Grenzen (in NVD unueblich, eher ein Datenfehler),
    werden beide geprueft: stimmen sie ueberein, gilt das Ergebnis, widersprechen sie sich -> "unknown".
    """
    if is_wildcard(version):
        return "unknown"
    has_bounds = any(not is_wildcard(b) for b in (start_including, start_excluding, end_including, end_excluding))
    if not is_wildcard(exact):
        c = compare(version, exact)
        by_exact: Status = "unknown" if c is None else ("affected" if c == 0 else "not_affected")
        if not has_bounds:
            return by_exact
        by_range = _check_bounds(version, start_including, start_excluding, end_including, end_excluding)
        return by_exact if by_exact == by_range else "unknown"
    if not has_bounds:
        return "affected"                    # CPE-Version "*" ohne Grenzen: alle Versionen betroffen
    return _check_bounds(version, start_including, start_excluding, end_including, end_excluding)


def _check_bounds(version: str, start_including: str | None, start_excluding: str | None,
                  end_including: str | None, end_excluding: str | None) -> Status:
    bounds = [
        (start_including, lambda c: c >= 0),
        (start_excluding, lambda c: c > 0),
        (end_including, lambda c: c <= 0),
        (end_excluding, lambda c: c < 0),
    ]
    unknown = False
    for bound, ok in bounds:
        if is_wildcard(bound):
            continue
        c = compare(version, bound)
        if c is None:
            unknown = True
        elif not ok(c):
            return "not_affected"            # eine sicher verletzte Grenze reicht
    return "unknown" if unknown else "affected"
