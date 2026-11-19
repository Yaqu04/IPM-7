"""Konfiguration von M4. Alle Werte kommen aus Umgebungsvariablen (.env), nie aus dem Code."""
from __future__ import annotations

import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://argos:argos@postgres:5432/argos")

# Gleicher Entwicklungs-Standard wie M2, M3 und n8n. Leer gesetzt = jede interne Anfrage wird abgelehnt.
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-internal-key")

# JWT fuer die Weboberflaeche. Der Standardwert ist nur fuer die lokale Entwicklung gedacht.
DEV_JWT_SECRET = "dev-jwt-secret-only-for-local-development"
JWT_SECRET = os.getenv("JWT_SECRET", DEV_JWT_SECRET)
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = max(5, int(os.getenv("M4_JWT_TTL_MINUTES", "480")))

# Erster Admin. Ohne ADMIN_PASSWORD wird beim ersten Start ein Zufallspasswort erzeugt und einmal ins Log geschrieben.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# Brute-Force-Schutz: nach so vielen Fehlversuchen wird das Konto kurz gesperrt.
LOGIN_MAX_FAILURES = max(1, int(os.getenv("M4_LOGIN_MAX_FAILURES", "5")))
LOGIN_LOCK_MINUTES = max(1, int(os.getenv("M4_LOGIN_LOCK_MINUTES", "15")))

MIN_PASSWORD_LENGTH = 10
