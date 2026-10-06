SET search_path TO firm_aetheris;

UPDATE job_artifacts SET ocr_status='pending', updated_at=NOW()
WHERE job_id='b8c65154-76a7-424b-a23b-231f268870c5'
  AND coalesce(ocr_status, '') IN ('skipped', 'na', '')
  AND lower(coalesce(extension, '')) IN (
        '.pdf', '.png', '.jpg', '.jpeg', '.tif', '.tiff', '.webp', '.bmp', '.gif', '.heic'
      )
  AND (
        lower(coalesce(extension, '')) = '.pdf'
        OR lower(file_path) LIKE '%/documents/%'
        OR lower(file_path) LIKE '%whatsapp%/documents/%'
        OR lower(file_path) LIKE '%/download%'
        OR lower(file_path) LIKE '%/downloads/%'
        OR lower(file_path) LIKE '%/desktop/%'
      )
  AND NOT (
        lower(file_path) LIKE '%/cache/%'
        OR lower(file_path) LIKE '%/.cache/%'
        OR lower(file_path) LIKE '%/.thumbnails/%'
        OR lower(file_path) LIKE '%/thumbs/%'
        OR lower(file_path) LIKE '%thumbcache%'
        OR lower(file_path) LIKE '%thumbs.db'
        OR lower(file_path) LIKE '%glide_disk_cache%'
        OR lower(file_path) LIKE '%/emoji/%'
        OR lower(file_path) LIKE '%/stickers/%'
        OR lower(file_path) LIKE '%/sticker/%'
        OR lower(file_path) LIKE '%/appdata/%'
        OR lower(file_path) LIKE '%appdata/%'
        OR lower(file_path) LIKE '%accountpictures%'
        OR lower(file_path) LIKE '%/application data/%'
        OR lower(file_path) LIKE '%/service worker/%'
        OR lower(file_path) LIKE '%/code cache/%'
        OR lower(file_path) LIKE '%/gpucache/%'
        OR lower(file_path) LIKE '%/shadercache/%'
        OR lower(file_path) LIKE '%/inetcache/%'
        OR lower(file_path) LIKE '%/temporary internet%'
        OR lower(file_path) LIKE '%/teams/backgrounds/%'
        OR lower(file_path) LIKE '%/node_modules/%'
        OR lower(file_path) LIKE '%/temp/%'
        OR lower(file_path) LIKE '%/tmp/%'
        OR lower(file_path) LIKE '%program files%'
        OR lower(file_path) LIKE '%programdata/%'
        OR lower(file_path) LIKE '%windows/system32%'
        OR lower(file_path) LIKE '%windows/syswow64%'
        OR lower(file_path) LIKE '%windows/winsxs%'
        OR lower(file_path) LIKE '%windows/servicing%'
        OR lower(file_path) LIKE '%windows/systemapps%'
        OR lower(file_path) LIKE '%$recycle.bin%'
        OR lower(file_path) LIKE '%system volume information%'
        OR lower(file_path) LIKE '%/plug_ins/%'
        OR lower(file_path) LIKE '%/stamps/%'
        OR lower(file_path) LIKE '%adobe/reader%'
        OR lower(file_path) LIKE '%adobe/acrobat%'
        OR lower(file_path) LIKE '%/windows/fonts/%'
        OR lower(file_path) LIKE '%/windows/installer/%'
        OR lower(coalesce(extension, '')) = '.ico'
        OR (
          coalesce(size_bytes, 0) > 0 AND coalesce(size_bytes, 0) < 4096
          AND lower(coalesce(extension, '')) <> '.pdf'
        )
      );

UPDATE jobs
SET status='indexing',
    updated_at=NOW(),
    pipeline_progress = jsonb_set(
      coalesce(pipeline_progress, '{}'::jsonb),
      '{label}',
      to_jsonb('OCR — GLM scans re-queued for CUDA'::text)
    )
WHERE id='b8c65154-76a7-424b-a23b-231f268870c5';

SELECT ocr_status, count(*)
FROM job_artifacts
WHERE job_id='b8c65154-76a7-424b-a23b-231f268870c5'
  AND lower(coalesce(extension, '')) IN (
        '.pdf', '.png', '.jpg', '.jpeg', '.tif', '.tiff', '.webp', '.bmp', '.gif', '.heic'
      )
GROUP BY 1
ORDER BY 2 DESC;
