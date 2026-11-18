"""Uebersetzung nach Deutsch ueber LibreTranslate fuer raw_items mit translation_status = 'pending'."""
import logging
import threading

from .config import settings
from .db import get_pool
from .httpclient import FetchError, Http

log = logging.getLogger("m1.translate")
_lock = threading.Lock()
MAX_CHUNK = 4000


def chunk_text(text: str, limit: int = MAX_CHUNK) -> list[str]:
    """Teilt an Absatz-, dann an Satz-/Wortgrenzen in Stuecke von hoechstens `limit` Zeichen."""
    chunks: list[str] = []
    cur = ""
    for para in text.split("\n"):
        while len(para) > limit:
            cut = max(para.rfind(". ", 0, limit), para.rfind(" ", 0, limit))
            cut = cut + 1 if cut > 0 else limit
            piece, para = para[:cut], para[cut:].lstrip()
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(piece)
        if cur and len(cur) + 1 + len(para) > limit:
            chunks.append(cur)
            cur = ""
        cur = f"{cur}\n{para}" if cur else para
    if cur:
        chunks.append(cur)
    return chunks


def translate_text(http: Http, text: str, source_lang: str | None) -> str:
    if not text.strip():
        return text
    out = []
    for chunk in chunk_text(text):
        resp = http.post(f"{settings().libretranslate_url}/translate", json={
            "q": chunk, "source": source_lang or "auto", "target": "de", "format": "text"})
        out.append(resp.json()["translatedText"])
    return "\n".join(out)


def _lt_lang(lang: str | None) -> str | None:
    return lang.split("-")[0] if lang else None   # 'zh-cn' -> 'zh' (LibreTranslate kennt keine Regionen)


def translate_pending(limit: int | None = None) -> dict:
    """Uebersetzt ausstehende Meldungen. Nach max. Versuchen oder bei nicht unterstuetzter Sprache
    wird der Status 'failed' (dann bleibt der Originaltext, M2 liest COALESCE(title_de, title))."""
    if not _lock.acquire(blocking=False):
        return {"skipped": "laeuft bereits"}
    s = settings()
    http = Http()
    done = failed = retry = 0
    items: list[dict] = []
    try:
        with get_pool().connection() as conn:
            rows = conn.execute(
                "SELECT id, lang, title, body, translation_attempts FROM raw_items "
                "WHERE translation_status = 'pending' ORDER BY id LIMIT %s",
                (limit or s.translate_batch,)).fetchall()
            conn.commit()
            for r in rows:
                try:
                    src = _lt_lang(r["lang"])
                    title_de = translate_text(http, r["title"], src)
                    body_de = translate_text(http, r["body"], src)
                    conn.execute(
                        "UPDATE raw_items SET title_de = %s, body_de = %s, translation_status = 'done', "
                        "translation_attempts = translation_attempts + 1 "
                        "WHERE id = %s AND translation_status = 'pending'",
                        (title_de, body_de, r["id"]))
                    done += 1
                    items.append({"id": r["id"], "lang": r["lang"], "title": r["title"],
                                  "title_de": title_de, "status": "done"})
                except Exception as exc:
                    permanent = isinstance(exc, FetchError) and exc.status == 400
                    give_up = permanent or r["translation_attempts"] + 1 >= s.translate_max_attempts
                    conn.execute(
                        "UPDATE raw_items SET translation_attempts = translation_attempts + 1, "
                        "translation_status = %s WHERE id = %s AND translation_status = 'pending'",
                        ("failed" if give_up else "pending", r["id"]))
                    failed += give_up
                    items.append({"id": r["id"], "lang": r["lang"], "title": r["title"],
                                  "status": "failed" if give_up else "retry", "error": str(exc)[:200]})
                    retry += not give_up
                    log.warning("Uebersetzung raw_items %s: %s", r["id"], exc)
                conn.commit()
    finally:
        http.close()
        _lock.release()
    return {"done": done, "failed": failed, "retry_later": retry, "items": items}
