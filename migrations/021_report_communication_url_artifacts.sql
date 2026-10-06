-- Report template Communication URL artifacts (section B).
INSERT INTO public.axiom_artifacts
    (artifact_id, platform, category, artifact_name, recovery_method,
     prompt_question, critical, sort_order, observation_focus, metadata, updated_at)
VALUES
    ('RPT-ART-004', 'Windows', 'Communication', 'Web Chat URLs', 'Parsing',
     'For the Windows forensic report artifact "Web Chat URLs" (Communication): report the total count recovered on this evidence, a concise explanation of what was found, and the forensic significance. Links to web-based chat platforms indicating chat usage.',
     TRUE, 1,
     'Links to web-based chat platforms indicating chat usage.',
     '{"source": "aetheris_report_template", "report_section": "B. ARTIFACTS"}'::jsonb, NOW()),
    ('RPT-ART-005', 'Windows', 'Communication', 'Social Media URLs', 'Parsing',
     'For the Windows forensic report artifact "Social Media URLs" (Communication): report the total count recovered on this evidence, a concise explanation of what was found, and the forensic significance. URLs linking to social media platforms.',
     TRUE, 2,
     'URLs linking to social media platforms.',
     '{"source": "aetheris_report_template", "report_section": "B. ARTIFACTS"}'::jsonb, NOW()),
    ('RPT-ART-013', 'Windows', 'Communication', 'Malware/Phishing URLs', 'Parsing',
     'For the Windows forensic report artifact "Malware/Phishing URLs" (Communication): report the total count recovered on this evidence, a concise explanation of what was found, and the forensic significance. Links designed to steal information or install harmful software.',
     TRUE, 3,
     'Links designed to steal information or install harmful software.',
     '{"source": "aetheris_report_template", "report_section": "B. ARTIFACTS"}'::jsonb, NOW())
ON CONFLICT (artifact_id) DO UPDATE SET
    platform = EXCLUDED.platform,
    category = EXCLUDED.category,
    artifact_name = EXCLUDED.artifact_name,
    prompt_question = EXCLUDED.prompt_question,
    critical = EXCLUDED.critical,
    sort_order = EXCLUDED.sort_order,
    observation_focus = EXCLUDED.observation_focus,
    metadata = EXCLUDED.metadata,
    updated_at = NOW();
