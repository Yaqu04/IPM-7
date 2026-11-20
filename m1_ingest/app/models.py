from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RawItem:
    """Eine normalisierte Meldung vor dem Speichern in raw_items."""
    external_id: str
    url: str
    title: str
    body: str = ""
    published_at: datetime | None = None
    lang: str | None = None          # nur setzen, wenn die Quelle die Sprache sicher kennt
    raw_payload: dict | None = None


@dataclass
class FetchResult:
    items: list[RawItem] = field(default_factory=list)
    state: dict | None = None        # wird als fetch_state gespeichert (None = alten Stand behalten)
    seen: int | None = None          # None = len(items)
    changed: int = 0                 # bei Faktenquellen: geaenderte/geschriebene CVEs
