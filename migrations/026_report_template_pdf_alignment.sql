-- Align report template mappings with reference PDFs (Seger = policy_violation, Histotechlab = data_exfiltration).

UPDATE public.case_types
SET default_report_type_id = 'policy_violation'
WHERE case_type_id = 'workplace_misconduct';

-- data_leakage case type stays on data_exfiltration (Histotechlab template objectives)
UPDATE public.case_types
SET default_report_type_id = 'data_exfiltration'
WHERE case_type_id = 'data_leakage';
