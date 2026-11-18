"""M3 Unternehmensabgleich, Lieferkette und Risiko: HTTP-Schnittstelle.

Aufrufer sind nur n8n (/run) und M4 (Import, Fehlalarme). Alle Endpunkte ausser /health
brauchen den Header X-API-Key. Details: m3_risk/README.md.
"""
from __future__ import annotations

import hmac
import logging
import os
import threading
from contextlib import contextmanager
from typing import Iterator

import psycopg
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row

from . import config, pipeline
from .inventory import CsvValidationError, apply_inventory, parse_csv
from .risk import load_policy

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("m3")

app = FastAPI(title="M3 Unternehmensabgleich, Lieferkette und Risiko")

POLICY = load_policy(config.RISK_POLICY_PATH)     # ungueltige Regeln -> Start schlaegt sofort fehl
RUN_MUTEX = threading.Lock()

CSV_TYPES = {"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain", "application/octet-stream"}


def authorize(x_api_key: str | None = Header(default=None)) -> None:
    expected = config.INTERNAL_API_KEY
    if not expected or not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="X-API-Key fehlt oder ist falsch")


@contextmanager
def exclusive_db() -> Iterator[psycopg.Connection]:
    """Verbindung mit exklusivem Zugriff fuer /run und Importe (Thread-Lock + PostgreSQL-Advisory-Lock)."""
    if not RUN_MUTEX.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="M3 verarbeitet gerade, bitte spaeter erneut versuchen")
    try:
        with psycopg.connect(config.DATABASE_URL, row_factory=dict_row, autocommit=True) as conn:
            if not conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (config.ADVISORY_LOCK_ID,)).fetchone()["ok"]:
                raise HTTPException(status_code=409, detail="M3 verarbeitet gerade (Datenbank-Sperre), bitte spaeter erneut versuchen")
            try:
                yield conn
            finally:
                conn.execute("SELECT pg_advisory_unlock(%s)", (config.ADVISORY_LOCK_ID,))
    finally:
        RUN_MUTEX.release()


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    # Details nur ins Log, nie Inventardaten in die Antwort
    log.exception("M3: unerwarteter Fehler bei %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Interner Fehler in M3, Details im Log"})


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m3_risk", "policy_version": POLICY.version}


@app.post("/run", dependencies=[Depends(authorize)])
def run() -> dict:
    with exclusive_db() as conn:
        return pipeline.run(conn, POLICY)


@app.post("/import/assets", dependencies=[Depends(authorize)])
async def import_assets(file: UploadFile = File(...)):
    name = (file.filename or "").lower()
    if not name.endswith(".csv") and (file.content_type or "").split(";")[0] not in CSV_TYPES:
        raise HTTPException(status_code=415, detail="CSV-Datei erwartet")
    data = await file.read(config.MAX_UPLOAD_BYTES + 1)
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Datei groesser als {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    try:
        inventory = parse_csv(data)
    except CsvValidationError as exc:
        return JSONResponse(status_code=422, content={"detail": exc.message, "errors": exc.errors})
    with exclusive_db() as conn:
        with conn.transaction():
            return apply_inventory(conn, inventory)


@app.post("/import/sbom", dependencies=[Depends(authorize)])
def import_sbom():
    raise HTTPException(status_code=501, detail="SBOM-Import folgt im naechsten PR")


@app.post("/suppressions", dependencies=[Depends(authorize)])
def create_suppression():
    raise HTTPException(status_code=501, detail="Fehlalarm-Markierung folgt im naechsten PR")


@app.delete("/suppressions/{suppression_id}", dependencies=[Depends(authorize)])
def delete_suppression(suppression_id: int):
    raise HTTPException(status_code=501, detail="Fehlalarm-Markierung folgt im naechsten PR")
