"""HTTP-Zugriff mit Wiederholung bei Netzwerkfehlern, 429 und 5xx."""
import time

import httpx

from .config import settings

RETRY_STATUS = {429, 500, 502, 503, 504}


class FetchError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class Http:
    def __init__(self, client: httpx.Client | None = None):
        s = settings()
        self.client = client or httpx.Client(
            timeout=s.http_timeout, follow_redirects=True, headers={"User-Agent": s.user_agent}
        )
        self.attempts = 1       # hoechste Versuchszahl eines einzelnen Requests
        self.status: int | None = None

    def close(self) -> None:
        self.client.close()

    def get(self, url: str, *, headers: dict | None = None, params: dict | None = None,
            allow_304: bool = False) -> httpx.Response:
        return self._request("GET", url, headers=headers, params=params, allow_304=allow_304)

    def post(self, url: str, *, json: dict | None = None, headers: dict | None = None) -> httpx.Response:
        return self._request("POST", url, headers=headers, json=json)

    def _request(self, method: str, url: str, allow_304: bool = False, **kw) -> httpx.Response:
        retries = max(1, settings().http_retries)
        last: Exception | None = None
        for attempt in range(1, retries + 1):
            self.attempts = max(self.attempts, attempt)
            try:
                resp = self.client.request(method, url, **kw)
            except httpx.TransportError as exc:
                last = FetchError(f"{type(exc).__name__}: {exc}")
            else:
                self.status = resp.status_code
                if resp.status_code == 304 and allow_304:
                    return resp
                if resp.status_code < 400:
                    return resp
                last = FetchError(f"HTTP {resp.status_code} fuer {url}", resp.status_code)
                if resp.status_code not in RETRY_STATUS:
                    raise last
                retry_after = resp.headers.get("Retry-After", "")
                if attempt < retries and retry_after.isdigit():
                    time.sleep(min(int(retry_after), 60))
                    continue
            if attempt < retries:
                time.sleep(2 ** attempt)
        assert last is not None
        raise last
