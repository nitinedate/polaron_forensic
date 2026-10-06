-- Case type taxonomy + report-type templates (PDF §3.1 intake, §9 catalogue).

CREATE TABLE IF NOT EXISTS public.report_type_templates (
    report_type_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    domain TEXT,
    description TEXT,
    default_os TEXT[] NOT NULL DEFAULT '{}',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.case_types (
    case_type_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    description TEXT,
    default_report_type_id TEXT REFERENCES public.report_type_templates(report_type_id),
    platforms TEXT[] NOT NULL DEFAULT '{}',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.report_type_mandatory_areas (
    report_type_id TEXT NOT NULL REFERENCES public.report_type_templates(report_type_id) ON DELETE CASCADE,
    area_code TEXT NOT NULL,
    objective_id TEXT,
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (report_type_id, area_code)
);

CREATE INDEX IF NOT EXISTS ix_case_types_sort ON public.case_types (sort_order);
CREATE INDEX IF NOT EXISTS ix_report_type_templates_sort ON public.report_type_templates (sort_order);

INSERT INTO public.report_type_templates
    (report_type_id, label, domain, description, default_os, sort_order)
VALUES
    ('general_computer_forensic', 'General Computer Forensic Report', 'forensic',
     'Standard workstation examination (Aetheris template).', ARRAY['windows'], 1),
    ('general', 'General Forensic Examination', 'general',
     'Alias for general computer forensic report.', ARRAY[]::TEXT[], 2),
    ('incident_response', 'Incident Response Report', 'cyber',
     'Security incident and compromise assessment.', ARRAY['windows'], 3),
    ('insider_threat', 'Insider Threat Report', 'hr',
     'Internal misuse, data theft, and policy violations.', ARRAY['windows'], 4),
    ('malware', 'Malware / Incident Response Report', 'malware',
     'Malware presence, persistence, and IOC analysis.', ARRAY['windows','linux'], 5),
    ('data_exfiltration', 'Data Exfiltration Report', 'dlp',
     'Unauthorized data staging, copy, upload, or email exfiltration.', ARRAY['windows'], 6),
    ('data_leakage', 'Data Leakage Report', 'dlp',
     'Alias for data exfiltration / leakage investigations.', ARRAY['windows'], 7),
    ('email_investigation', 'Email Investigation Report', 'communication',
     'Local and webmail email artifact examination.', ARRAY['windows'], 8),
    ('cloud_forensic', 'Cloud Forensic Report', 'cloud',
     'Cloud account, sync, and remote storage activity.', ARRAY['windows'], 9),
    ('mobile_forensic', 'Mobile Device Forensic Report', 'mobile',
     'Mobile messaging, location, and app artifacts.', ARRAY['android','ios'], 10)
ON CONFLICT (report_type_id) DO UPDATE SET
    label = EXCLUDED.label,
    domain = EXCLUDED.domain,
    description = EXCLUDED.description,
    default_os = EXCLUDED.default_os,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

INSERT INTO public.case_types
    (case_type_id, label, description, default_report_type_id, platforms, sort_order)
VALUES
    ('general_computer_forensic', 'General Computer Forensic', 'Standard computer forensic examination.',
     'general_computer_forensic', ARRAY['windows','macos','linux'], 1),
    ('workplace_misconduct', 'Workplace Misconduct', 'Policy violations and unauthorized activity on corporate assets.',
     'general_computer_forensic', ARRAY['windows'], 2),
    ('data_leakage', 'Data Leakage / Exfiltration', 'Suspected unauthorized copy, upload, or transfer of sensitive data.',
     'data_exfiltration', ARRAY['windows'], 3),
    ('insider_threat', 'Insider Threat', 'Internal actor misuse, privilege abuse, or sabotage.',
     'insider_threat', ARRAY['windows'], 4),
    ('malware_incident', 'Malware / Security Incident', 'Compromise, ransomware, or malicious software investigation.',
     'malware', ARRAY['windows','linux'], 5),
    ('email_investigation', 'Email Investigation', 'Email misuse, forwarding, or mailbox examination.',
     'email_investigation', ARRAY['windows'], 6),
    ('cloud_account', 'Cloud Account Investigation', 'OneDrive, Google Drive, Dropbox, or SaaS account activity.',
     'cloud_forensic', ARRAY['windows'], 7),
    ('mobile_device', 'Mobile Device Examination', 'Smartphone or tablet messaging and app artifacts.',
     'mobile_forensic', ARRAY['android','ios'], 8),
    ('intellectual_property', 'Intellectual Property Theft', 'Trade secret or proprietary data misappropriation.',
     'data_exfiltration', ARRAY['windows'], 9),
    ('harassment_bullying', 'Harassment / Bullying', 'Communication and messaging evidence review.',
     'email_investigation', ARRAY['windows','android','ios'], 10)
ON CONFLICT (case_type_id) DO UPDATE SET
    label = EXCLUDED.label,
    description = EXCLUDED.description,
    default_report_type_id = EXCLUDED.default_report_type_id,
    platforms = EXCLUDED.platforms,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

INSERT INTO public.report_type_mandatory_areas (report_type_id, area_code, objective_id, sort_order)
VALUES
    ('general_computer_forensic', 'USER_ACCOUNT_ACTIVITY', NULL, 1),
    ('general_computer_forensic', 'FILE_ACCESS_HANDLING', NULL, 2),
    ('general_computer_forensic', 'USB_EXTERNAL_DEVICES', NULL, 3),
    ('data_exfiltration', 'DATA_EXFILTRATION', NULL, 1),
    ('data_exfiltration', 'USB_EXTERNAL_DEVICES', NULL, 2),
    ('data_exfiltration', 'CLOUD_REMOTE_STORAGE', NULL, 3),
    ('data_exfiltration', 'EMAIL_ACTIVITY', NULL, 4),
    ('insider_threat', 'FILE_ACCESS_HANDLING', NULL, 1),
    ('insider_threat', 'USB_EXTERNAL_DEVICES', NULL, 2),
    ('insider_threat', 'EMAIL_ACTIVITY', NULL, 3),
    ('malware', 'MALWARE_SECURITY', NULL, 1),
    ('malware', 'USER_ACCOUNT_ACTIVITY', NULL, 2),
    ('email_investigation', 'EMAIL_ACTIVITY', NULL, 1),
    ('email_investigation', 'COMMUNICATION_MESSAGING', NULL, 2),
    ('mobile_forensic', 'COMMUNICATION_MESSAGING', NULL, 1),
    ('cloud_forensic', 'CLOUD_REMOTE_STORAGE', NULL, 1)
ON CONFLICT (report_type_id, area_code) DO UPDATE SET
    objective_id = EXCLUDED.objective_id,
    sort_order = EXCLUDED.sort_order;
