"""Connector-Register: sources.connector -> fetch(source, state, http, conn) -> FetchResult."""
from . import cisa_kev, epss, nvd, osv, rss

CONNECTORS = {
    "rss": rss.fetch,
    "cisa_kev": cisa_kev.fetch,
    "nvd": nvd.fetch,
    "epss": epss.fetch,
    "osv": osv.fetch,
}
