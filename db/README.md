# db

SQL-Dateien in init/ laufen beim allerersten Start von PostgreSQL in alphabetischer Reihenfolge
(docker compose down -v setzt die Datenbank zurueck).
Jedes Modul hat eine eigene Datei: m1_initial.sql (public), m2_initial.sql (Schema m2),
m3_initial.sql (Schema m3), m4_initial.sql (Schema m4).
