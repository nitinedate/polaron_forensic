-- Polaron/Aetheris v1.5.0: Nessus CVSS severity + transparent weighted Risk Number.
-- Safe/idempotent backfill of existing findings. No rows are deleted.

CREATE OR REPLACE FUNCTION public.apply_firm_nessus_risk_v150(schema_name text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=schema_name AND table_name='vuln_findings') THEN
        RETURN;
    END IF;

    EXECUTE format($sql$
        WITH source AS (
            SELECT f.id,
                   COALESCE(f.cvss, 0)::float AS cvss,
                   COALESCE(f.is_kev, false) AS is_kev,
                   COALESCE(NULLIF(lower(trim(a.external_exposure)), ''), 'internal') AS exposure_key,
                   COALESCE(NULLIF(lower(replace(trim(a.criticality), ' ', '')), ''), 'tier2') AS criticality_key,
                   GREATEST(0, EXTRACT(EPOCH FROM (now() - COALESCE(f.first_seen_at, f.created_at, now()))) / 86400.0) AS days_open,
                   COALESCE(f.risk_factors_json, '{}'::jsonb) AS rf
              FROM %I.vuln_findings f
              LEFT JOIN %I.vuln_assets a ON a.id = f.asset_id
        ), factors AS (
            SELECT *,
                   LEAST(GREATEST(cvss,0),10) / 10.0 * 25.0 AS technical,
                   CASE
                     WHEN COALESCE(rf->>'vpr', rf->>'vpr_score', '') ~ '^[0-9]+([.][0-9]+)?$'
                       THEN LEAST(GREATEST(COALESCE(NULLIF(rf->>'vpr',''), NULLIF(rf->>'vpr_score',''))::float,0),10) / 10.0 * 20.0
                     WHEN COALESCE(rf->>'epss', rf->>'epss_percentile', '') ~ '^[0-9]+([.][0-9]+)?$'
                       THEN CASE
                              WHEN COALESCE(NULLIF(rf->>'epss',''), NULLIF(rf->>'epss_percentile',''))::float <= 1
                                THEN LEAST(GREATEST(COALESCE(NULLIF(rf->>'epss',''), NULLIF(rf->>'epss_percentile',''))::float,0),1) * 20.0
                              ELSE LEAST(GREATEST(COALESCE(NULLIF(rf->>'epss',''), NULLIF(rf->>'epss_percentile',''))::float,0),100) / 100.0 * 20.0
                            END
                     ELSE CASE lower(replace(COALESCE(rf->>'exploit_maturity',''), '_','-'))
                            WHEN 'unproven' THEN 2.0
                            WHEN 'proof-of-concept' THEN 8.0
                            WHEN 'poc' THEN 8.0
                            WHEN 'functional' THEN 14.0
                            WHEN 'weaponized' THEN 20.0
                            WHEN 'high' THEN 20.0
                            WHEN 'active' THEN 20.0
                            ELSE 0.0
                          END
                   END AS threat,
                   CASE WHEN is_kev THEN 15.0 ELSE 0.0 END AS known_exploitation,
                   CASE exposure_key
                     WHEN 'internet-facing' THEN 15.0 WHEN 'partner' THEN 10.0
                     WHEN 'isolated' THEN 1.0 ELSE 5.0 END AS exposure,
                   CASE criticality_key
                     WHEN 'tier0' THEN 15.0 WHEN '0' THEN 15.0
                     WHEN 'tier1' THEN 12.0 WHEN '1' THEN 12.0
                     WHEN 'tier3' THEN 4.0 WHEN '3' THEN 4.0
                     ELSE 8.0 END AS impact,
                   LEAST(days_open / 30.0 * 5.0, 5.0) AS age,
                   CASE WHEN COALESCE(rf->>'control_adjustment','') ~ '^-?[0-9]+([.][0-9]+)?$'
                        THEN LEAST(0.0, GREATEST(-10.0, (rf->>'control_adjustment')::float)) ELSE 0.0 END AS control_adjustment,
                   CASE
                     WHEN COALESCE(rf->>'confidence_adjustment','') ~ '^-?[0-9]+([.][0-9]+)?$'
                       THEN LEAST(5.0, GREATEST(-5.0, (rf->>'confidence_adjustment')::float))
                     WHEN COALESCE(rf->>'quality_of_detection', rf->>'qod', '') ~ '^[0-9]+([.][0-9]+)?$'
                       THEN CASE
                              WHEN COALESCE(NULLIF(rf->>'quality_of_detection',''), NULLIF(rf->>'qod',''))::float >= 90 THEN 5.0
                              WHEN COALESCE(NULLIF(rf->>'quality_of_detection',''), NULLIF(rf->>'qod',''))::float >= 70 THEN 3.0
                              WHEN COALESCE(NULLIF(rf->>'quality_of_detection',''), NULLIF(rf->>'qod',''))::float >= 50 THEN 0.0
                              WHEN COALESCE(NULLIF(rf->>'quality_of_detection',''), NULLIF(rf->>'qod',''))::float >= 30 THEN -2.0
                              ELSE -5.0 END
                     WHEN COALESCE(rf->>'confidence','') ~ '^-?[0-9]+([.][0-9]+)?$'
                       THEN LEAST(5.0, GREATEST(-5.0, (rf->>'confidence')::float))
                     ELSE 0.0
                   END AS confidence
              FROM source
        ), scored AS (
            SELECT *, LEAST(100.0, GREATEST(0.0,
                     technical + threat + known_exploitation + exposure + impact + age + control_adjustment + confidence
                   )) AS risk_number
              FROM factors
        )
        UPDATE %I.vuln_findings f
           SET severity = CASE
                            WHEN s.cvss >= 9.0 THEN 'critical'
                            WHEN s.cvss >= 7.0 THEN 'high'
                            WHEN s.cvss >= 4.0 THEN 'medium'
                            WHEN s.cvss > 0.0 THEN 'low'
                            ELSE 'info' END,
               enterprise_risk_score = round(s.risk_number::numeric, 2)::float,
               risk_band = CASE
                             WHEN s.risk_number >= 80 THEN 'critical'
                             WHEN s.risk_number >= 60 THEN 'high'
                             WHEN s.risk_number >= 35 THEN 'medium'
                             WHEN s.risk_number > 0 THEN 'low'
                             ELSE 'info' END,
               risk_factors_json = COALESCE(f.risk_factors_json, '{}'::jsonb) || jsonb_build_object(
                    'model_version','nessus-aligned-weighted-1',
                    'severity_model','nessus-cvss',
                    'technical',round(s.technical::numeric,2),
                    'threat',round(s.threat::numeric,2),
                    'known_exploitation',s.known_exploitation,
                    'exposure',s.exposure,
                    'impact',s.impact,
                    'age',round(s.age::numeric,2),
                    'control_adjustment',round(s.control_adjustment::numeric,2),
                    'confidence',round(s.confidence::numeric,2),
                    'risk_number',round(s.risk_number::numeric,2)
               ),
               updated_at = now()
          FROM scored s
         WHERE f.id = s.id
    $sql$, schema_name, schema_name, schema_name);
END;
$fn$;

CREATE OR REPLACE FUNCTION public.apply_firm_nessus_risk_v150_all()
RETURNS void
LANGUAGE plpgsql
AS $fn$
DECLARE r record;
BEGIN
    FOR r IN SELECT schema_name FROM information_schema.schemata WHERE left(schema_name, 5) = 'firm_' LOOP
        PERFORM public.apply_firm_nessus_risk_v150(r.schema_name);
    END LOOP;
END;
$fn$;

SELECT public.apply_firm_nessus_risk_v150_all();
