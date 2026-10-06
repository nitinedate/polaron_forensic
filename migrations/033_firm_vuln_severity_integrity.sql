-- Aetheris 2026-08-31: promote stored severity when numeric CVSS is more severe.
-- Safe/idempotent: never downgrades an existing scanner severity.

UPDATE vuln_findings
SET severity = CASE
    WHEN cvss >= 9.0 THEN 'critical'
    WHEN cvss >= 7.0 THEN 'high'
    WHEN cvss >= 4.0 THEN 'medium'
    WHEN cvss > 0.0 THEN 'low'
    ELSE severity
  END,
  updated_at = NOW()
WHERE cvss IS NOT NULL
  AND cvss > 0
  AND CASE lower(coalesce(severity, 'info'))
        WHEN 'critical' THEN 4
        WHEN 'high' THEN 3
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 1
        ELSE 0
      END
      < CASE
          WHEN cvss >= 9.0 THEN 4
          WHEN cvss >= 7.0 THEN 3
          WHEN cvss >= 4.0 THEN 2
          WHEN cvss > 0.0 THEN 1
          ELSE 0
        END;
