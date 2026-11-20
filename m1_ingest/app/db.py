"""Verbindungspool zu PostgreSQL (lazy, damit /health auch ohne Datenbank antwortet)."""
import threading

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings

_pool: ConnectionPool | None = None
_lock = threading.Lock()


def get_pool() -> ConnectionPool:
    global _pool
    with _lock:
        if _pool is None:
            _pool = ConnectionPool(
                settings().database_url,
                min_size=1,
                max_size=8,
                kwargs={"row_factory": dict_row},
                open=False,
            )
            _pool.open(wait=False)
        return _pool


def close_pool() -> None:
    global _pool
    with _lock:
        if _pool is not None:
            _pool.close()
            _pool = None
