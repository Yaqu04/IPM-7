"""Normalisierung von Hersteller- und Produktnamen und Zerlegung von CPE-2.3-Strings.

Ziel ist dieselbe Schreibweise wie in cve_affected.vendor / cve_affected.product (NVD-CPE):
klein, Leerzeichen als Unterstrich, bekannte Abweichungen ueber VENDOR_ALIASES,
z. B. "Apache Software Foundation" -> "apache", "Fortinet, Inc." -> "fortinet",
"Exchange Server" -> "exchange_server".
"""
from __future__ import annotations

import re

# Rechtsformen am Ende eines Herstellernamens werden entfernt ("Fortinet, Inc." -> "fortinet").
LEGAL_SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc",
    "gmbh", "ag", "se", "sa", "plc", "bv", "oy", "ab", "kg",
}

# Bekannte Abweichungen zwischen ueblichen Herstellernamen und dem Herstellerfeld in NVD-CPEs.
# Fuer exakte Zuordnung im Inventar besser die Spalte cpe23 ausfuellen.
VENDOR_ALIASES = {
    "apache_software_foundation": "apache",
    "the_apache_software_foundation": "apache",
    "vmware_by_broadcom": "vmware",
    "citrix_systems": "citrix",
    "cisco_systems": "cisco",
    "ivanti_software": "ivanti",
    "palo_alto": "paloaltonetworks",
    "palo_alto_networks": "paloaltonetworks",
    "check_point_software_technologies": "checkpoint",
    "check_point": "checkpoint",
    "sonicwall_inc": "sonicwall",
    "atlassian_corporation": "atlassian",
    "the_postgresql_global_development_group": "postgresql",
    "postgresql_global_development_group": "postgresql",
}

_ALLOWED = re.compile(r"[^a-z0-9._+\-]+")
_UNDERSCORES = re.compile(r"_+")


def _clean(value: str) -> str:
    value = value.strip().lower().replace("&", "and")
    value = _ALLOWED.sub("_", value)
    value = _UNDERSCORES.sub("_", value)
    return value.strip("_.-")


def normalize_vendor(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    tokens = _clean(value).split("_")
    while len(tokens) > 1 and tokens[-1].strip(".") in LEGAL_SUFFIXES:
        tokens.pop()
    result = "_".join(tokens).strip("_.-")
    return VENDOR_ALIASES.get(result, result) or None


def normalize_product(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    return _clean(value) or None


_CPE_FIELDS = ("part", "vendor", "product", "version", "update", "edition", "language",
               "sw_edition", "target_sw", "target_hw", "other")


def _split_cpe(value: str) -> list[str]:
    """Trennt an ':' und beachtet maskierte Zeichen (z. B. '\\:' innerhalb eines Feldes)."""
    parts, buf, escaped = [], [], False
    for ch in value:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def parse_cpe23(cpe: str | None) -> dict[str, str] | None:
    """Zerlegt 'cpe:2.3:part:vendor:product:version:...'. Gibt None zurueck, wenn der String ungueltig ist."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return None
    parts = _split_cpe(cpe)
    if len(parts) != 13:
        return None
    fields = dict(zip(_CPE_FIELDS, parts[2:]))
    if fields["part"] not in {"a", "o", "h"} or not fields["vendor"] or not fields["product"]:
        return None
    fields["vendor"] = fields["vendor"].lower()
    fields["product"] = fields["product"].lower()
    return fields


def is_wildcard(value: str | None) -> bool:
    """'*' (beliebig), '-' (nicht anwendbar) und leere Werte sind keine konkrete Version."""
    return value is None or value.strip() in {"", "*", "-"}
