"""Normalisierung: HTML entfernen, Hash, CVE-IDs, Spracherkennung."""
import hashlib
import re
import unicodedata
from html import unescape
from html.parser import HTMLParser

from langdetect import DetectorFactory, detect
from langdetect.lang_detect_exception import LangDetectException

DetectorFactory.seed = 0

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
LANG_RE = re.compile(r"^[a-z]{2}(-[a-z]{2})?$")
_BLOCK = {"p", "br", "li", "div", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "table"}


class _Stripper(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in _BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag in _BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def strip_html(text: str | None) -> str:
    """Entfernt Tags, dekodiert Entities, normalisiert Leerraum (Absaetze bleiben erhalten)."""
    if not text:
        return ""
    stripper = _Stripper()
    stripper.feed(text)
    stripper.close()
    raw = "".join(stripper.parts).replace("\xa0", " ")
    lines = [re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in raw.split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def _canon(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).strip().casefold()


def content_hash(title: str, body: str) -> str:
    """SHA-256 (hex) von normalisiertem Titel und Text."""
    return hashlib.sha256(f"{_canon(title)}\n{_canon(body)}".encode()).hexdigest()


def extract_cve_ids(*texts: str | None) -> list[str]:
    found = {m.group(0).upper() for t in texts if t for m in CVE_RE.finditer(t)}
    return sorted(found)


def valid_lang(code: str | None) -> str | None:
    code = (code or "").strip().lower().replace("_", "-")
    return code if LANG_RE.match(code) else None


def detect_language(title: str, body: str, fallback: str | None = None) -> str | None:
    """Erkennt die Sprache; bei zu wenig Text gilt die Sprache der Quelle (oder None)."""
    sample = f"{title}\n{body}"[:1500].strip()
    if len(sample) >= 20:
        try:
            return valid_lang(detect(sample))
        except LangDetectException:
            pass
    return valid_lang(fallback)
