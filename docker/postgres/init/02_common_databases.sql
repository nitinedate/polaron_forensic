-- The application uses one database on the shared Postgres.
-- Disk, Android, iOS, vulnerability, and mobile extraction all connect to `forensic`.
\c forensic
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;
