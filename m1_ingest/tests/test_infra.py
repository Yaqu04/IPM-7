import httpx
import pytest

from app import httpclient
from app.httpclient import FetchError, Http
from app.translate import chunk_text


def make(handler):
    return Http(httpx.Client(transport=httpx.MockTransport(handler)))


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(httpclient.time, "sleep", lambda s: None)


def test_retries_5xx_then_succeeds():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(503 if len(calls) < 3 else 200, json={"ok": 1})

    h = make(handler)
    assert h.get("http://x").json() == {"ok": 1}
    assert h.attempts == 3


def test_no_retry_on_404():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(404)

    h = make(handler)
    with pytest.raises(FetchError) as e:
        h.get("http://x")
    assert e.value.status == 404 and len(calls) == 1


def test_gives_up_after_retries():
    h = make(lambda r: httpx.Response(500))
    with pytest.raises(FetchError) as e:
        h.get("http://x")
    assert e.value.status == 500 and h.attempts == 3


def test_304_allowed():
    assert make(lambda r: httpx.Response(304)).get("http://x", allow_304=True).status_code == 304


def test_chunk_text_respects_limit_and_keeps_content():
    text = "\n".join(["Satz eins. " * 30, "kurz", "wort " * 2000])
    chunks = chunk_text(text, 500)
    assert all(len(c) <= 500 for c in chunks)
    squash = lambda s: s.replace("\n", "").replace(" ", "")
    assert squash("".join(chunks)) == squash(text)


def test_summarize_counts_and_empty():
    from app.ingest import summarize
    assert summarize([]) == {"sources": 0, "success": 0, "failed": 0, "skipped": 0,
                             "new_items": 0, "runs": []}
    runs = [{"status": "success", "new_items": [{"id": 1}, {"id": 2}]},
            {"status": "failed", "error": "x"}, {"status": "skipped"}]
    s = summarize(runs)
    assert (s["sources"], s["success"], s["failed"], s["skipped"], s["new_items"]) == (3, 1, 1, 1, 2)
