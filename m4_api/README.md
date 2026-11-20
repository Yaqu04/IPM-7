# M4 Zentrale API und Benachrichtigung

REST-API fuer die Weboberflaeche, Konfiguration, Benachrichtigungen, Berichte.

Platzhalter: bisher gibt es nur GET /health. Weitere Endpunkte und Logik kommen bei der Umsetzung.

## Datenbank

Schema `m4` in [db/init/m4_initial.sql](../db/init/m4_initial.sql). M4 schreibt nur dort und in `public.sources`.
M3 wird ausschliesslich ueber die Views `m3.findings_current`, `m3.findings_history` und `m3.assets_overview` gelesen.

| Tabelle | Zweck |
|---|---|
| `users` | Anmeldung, Rollen `admin`, `analyst`, `viewer` |
| `recipient_groups`, `recipients` | Empfaenger je Zielgruppe (`it_security`, `management`, `executive`) |
| `notification_rules` | Risikostufe -> Gruppe, Kanal, sofort/taeglich/woechentlich |
| `notification_log` | Versandprotokoll (im Arbeitspaket `notifications`) |
| `item_status` | Bearbeitungsstatus je Meldung (im Arbeitspaket `alert_status`) |
| `audit_log` | Aenderungsprotokoll, nur anhaengen |

**Genau einmal benachrichtigen:** M3 legt bei jeder Aenderung der Eingangswerte (z. B. neuer EPSS-Wert)
eine neue `risk_assessment_id` an. Gemeldet wird deshalb je Treffer (`match_id`), Empfaenger und Kanal nur
beim ersten Mal und wenn die Risikostufe hoeher ist als die zuletzt gemeldete.

**Rauchtest** (Testdaten werden zurueckgerollt):
```sh
docker compose down -v
docker compose up -d postgres
docker compose exec -T postgres psql -U argos -d argos -v ON_ERROR_STOP=1 < m4_api/tests/m4_schema_smoke.sql
```
Erwartet: `NOTICE:  M4 smoke test OK`.
