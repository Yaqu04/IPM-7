"""M4 Zentrale API und Benachrichtigung.

Routen fuer die Weboberflaeche liegen unter /api (nginx reicht /api/ unveraendert durch) und brauchen ein JWT.
Interne Routen (/health, spaeter /notify fuer n8n) liegen ohne Praefix. Details: m4_api/README.md.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import audit, config, db, security
from .routers import auth, sources, users

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("m4")


def ensure_admin(conn: psycopg.Connection) -> None:
    """Legt den ersten Admin aus der .env an, solange es keinen aktiven Admin gibt."""
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(42004004)")   # mehrere Starts gleichzeitig: nur einer legt an
        if conn.execute("SELECT 1 FROM m4.users WHERE role = 'admin' AND is_active").fetchone():
            return
        password = config.ADMIN_PASSWORD
        if not password:
            password = secrets.token_urlsafe(16)
            log.warning("ADMIN_PASSWORD ist nicht gesetzt. Einmaliges Startpasswort fuer '%s': %s",
                        config.ADMIN_USERNAME, password)
        row = conn.execute(
            """INSERT INTO m4.users (username, password_hash, role) VALUES (%s, %s, 'admin')
               ON CONFLICT ((lower(username))) DO NOTHING RETURNING id""",
            (config.ADMIN_USERNAME, security.hash_password(password)),
        ).fetchone()
        if row is None:
            log.warning("Kein aktiver Admin, aber Benutzer '%s' existiert schon (inaktiv oder andere Rolle). "
                        "Bitte manuell pruefen.", config.ADMIN_USERNAME)
            return
        audit.write(conn, None, None, "create", "user", row["id"],
                    {"username": config.ADMIN_USERNAME, "role": "admin", "bootstrap": True}, username="system")
        log.info("Start-Admin '%s' angelegt", config.ADMIN_USERNAME)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if config.JWT_SECRET == config.DEV_JWT_SECRET:
        log.warning("JWT_SECRET hat den Entwicklungs-Standardwert. Fuer den Betrieb in der .env setzen.")
    elif len(config.JWT_SECRET.encode()) < 32:
        log.warning("JWT_SECRET ist kuerzer als 32 Byte und damit zu schwach fuer HS256.")
    for attempt in range(10):
        try:
            with db.connect() as conn:
                ensure_admin(conn)
            break
        except psycopg.OperationalError:
            if attempt == 9:
                raise
            log.info("Datenbank noch nicht erreichbar, neuer Versuch in 2 s")
            time.sleep(2)
    yield


app = FastAPI(title="M4 Zentrale API und Benachrichtigung", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(sources.router)


@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    log.exception("M4: unerwarteter Fehler bei %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Interner Fehler in M4, Details im Log"})


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "m4_api"}
