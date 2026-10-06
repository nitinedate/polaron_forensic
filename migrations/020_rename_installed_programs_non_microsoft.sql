-- Align AX-0011 catalog label with AXIOM/report template naming.
UPDATE public.axiom_artifacts
SET artifact_name = 'Installed Programs (Non-Microsoft)',
    observation_focus = replace(
        coalesce(observation_focus, ''),
        'Windows > Application Usage > Installed Programs',
        'Windows > Application Usage > Installed Programs (Non-Microsoft)'
    ),
    prompt_question = replace(
        coalesce(prompt_question, ''),
        '"Installed Programs"',
        '"Installed Programs (Non-Microsoft)"'
    ),
    updated_at = NOW()
WHERE artifact_id = 'AX-0011'
  AND platform = 'Windows';
