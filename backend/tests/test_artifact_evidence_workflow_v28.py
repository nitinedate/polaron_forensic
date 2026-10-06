from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_disk_and_mobile_artifact_menus_are_first_class_and_separate():
    layout = read("frontend/src/components/AppLayout.tsx")
    assert 'to: "/forensic/artifacts", label: "Artifacts"' in layout
    assert 'to: "/mobile/artifacts", label: "Mobile Artifacts"' in layout
    assert 'requiredPerm: "artifact:read"' in layout
    assert '"/forensic/artifacts": "Disk Artifacts"' in layout
    assert '"/mobile/artifacts": "Mobile Artifacts"' in layout


def test_routes_use_different_disk_and_mobile_artifact_pages():
    app = read("frontend/src/App.tsx")
    assert 'path="forensic/artifacts"' in app
    assert '<DiskArtifactsHubPage />' in app
    assert 'path="mobile/artifacts"' in app
    assert '<MobileArtifactsDirectoryPage />' in app
    for route in (
        'mobile/android/jobs/:jobId/artifacts',
        'mobile/ios/jobs/:jobId/artifacts',
        'mobile/jobs/:jobId/artifacts',
    ):
        assert f'path="{route}"' in app
    assert '<MobileArtifactsPage />' in app


def test_processing_pages_only_lead_forward_to_artifacts_not_intake_or_report():
    disk = read("frontend/src/pages/forensic/JobDetailPage.tsx")
    start = disk.rindex("<PageHeader")
    end = disk.index("{canRun &&", start)
    actions = disk[start:end]
    assert f'/forensic/jobs/${{job.id}}/artifacts' in actions
    assert "/intake" not in actions
    assert "/report" not in actions

    mobile = read("frontend/src/pages/mobile/MobileCompactJobPage.tsx")
    assert 'to={`${base}/jobs/${jobId}/artifacts`}' in mobile
    assert 'to={`${base}/jobs/${jobId}/report`}' not in mobile
    assert 'to={`${base}/jobs/${jobId}/intake`}' not in mobile


def test_artifacts_then_intake_then_report_is_the_only_forward_workflow():
    disk_artifacts = read("frontend/src/pages/forensic/ArtifactExplorerPage.tsx")
    mobile_artifacts = read("frontend/src/pages/mobile/MobileArtifactsPage.tsx")
    intake = read("frontend/src/pages/forensic/JobIntakePage.tsx")
    assert 'to={`/forensic/jobs/${jobId}/intake`}' in disk_artifacts
    assert 'to={`${base}/jobs/${jobId}/intake`}' in mobile_artifacts
    assert "artifactsHref" in intake
    assert "reportHref" in intake
    assert "Continue to Report" in intake
    assert "reportReady" in intake


def test_disk_artifact_hub_has_case_id_filter():
    page = read("frontend/src/pages/forensic/DiskArtifactsHubPage.tsx")
    assert "Filter by Case ID" in page
    assert "Case ID or job ID" in page
    assert "Processing Pipeline → Artifacts → Intake → Report" in page


def test_mobile_artifact_workspace_has_whatsapp_media_and_separate_deleted_section():
    page = read("frontend/src/pages/mobile/MobileArtifactsPage.tsx")
    for token in (
        'whatsapp_messages',
        'whatsapp_deleted_messages',
        'deleted_photos',
        'deleted_videos',
        'deleted_documents',
        'deleted_files',
        'Pictures / images',
        'Videos',
        'Audio',
        'Documents',
        'Deleted evidence',
    ):
        assert token in page
    assert "platform-specific backend" in page
    assert 'service=`mobile-${platform}`' in page


def test_whatsapp_thread_is_rendered_as_sender_aligned_chat_bubbles_with_deleted_marking():
    dialog = read("frontend/src/components/forensic/FamilyEvidenceDialog.tsx")
    assert 'fromMe ? "justify-end" : "justify-start"' in dialog
    assert 'bg-[#d9fdd3]' in dialog
    assert 'bg-[#efeae2]' in dialog
    assert 'deleted by me' in dialog
    assert 'Recovery:' in dialog
    assert 'Full file linked — click to download original' in dialog


def test_actual_media_properties_and_download_endpoints_are_available():
    router = read("backend/app/routers/artifacts.py")
    media = read("backend/app/services/artifact_media_properties.py")
    preview = read("frontend/src/components/forensic/ArtifactPreviewPanel.tsx")
    dockerfile = read("backend/Dockerfile")
    assert '@router.get("/{job_id}/artifacts/{artifact_id}/properties")' in router
    for token in ("size_bytes", "width", "height", "pixels", "duration_seconds", "downloadable"):
        assert f'"{token}"' in media
    assert "ffprobe" in media
    assert "ffmpeg" in dockerfile
    assert "Actual size" in preview
    assert "pixels" in preview
    assert "downloadArtifactContent" in preview
    assert "downloadEmailAttachmentContent" in preview


def test_recovered_email_html_is_sandboxed_and_attachments_are_downloadable():
    preview = read("frontend/src/components/forensic/ArtifactPreviewPanel.tsx")
    api = read("frontend/src/lib/forensicApi.ts")
    assert 'sandbox=""' in preview
    assert 'Content-Security-Policy' in preview
    assert "dangerouslySetInnerHTML" not in preview
    assert "downloadEmailAttachmentContent" in api


def test_review_signals_cover_requested_forensic_classes_without_claiming_maliciousness():
    review = read("backend/app/services/artifact_review.py")
    for token in (
        "extension_mismatch",
        "double_extension",
        "shortcut_execution",
        "email_content",
        "command_execution",
        "url_anomaly",
        "social_web",
        "log_signal",
        "media_content_review",
        "deleted_recovered",
    ):
        assert token in review
    assert "triage aids, not conclusions" in review


def test_case_review_summary_is_bounded_in_python_for_large_cases():
    review = read("backend/app/services/artifact_review.py")
    summary = review[review.index("def job_review_summary"):]
    assert "SELECT count(*) AS c FROM job_artifacts" in summary
    assert "candidate_predicate" in summary
    assert "scan_cap =" in summary
    assert "LIMIT :scan_cap" in summary
    assert '"candidate_total"' in summary
    assert '"scanned_candidates"' in summary
    assert "SELECT count(*) AS c FROM job_artifacts WHERE job_id=:jid AND" not in summary
    # Regression: never return to fetching every artifact row into Python.
    assert "FROM job_artifacts WHERE job_id=:jid ORDER BY created_at DESC" not in summary


def test_mobile_platform_artifact_routes_remain_android_ios_isolated():
    app = read("frontend/src/App.tsx")
    directory = read("frontend/src/pages/mobile/MobileArtifactsDirectoryPage.tsx")
    page = read("frontend/src/pages/mobile/MobileArtifactsPage.tsx")
    assert 'mobile/android/jobs/:jobId/artifacts' in app
    assert 'mobile/ios/jobs/:jobId/artifacts' in app
    assert 'const serviceFor = (platform: Platform) => `mobile-${platform}` as ApiService;' in directory
    assert 'const platforms: Platform[] = dedicated ? [dedicated] : ["android", "ios"];' in directory
    assert 'service: serviceFor(platform)' in directory
    assert 'const service=`mobile-${platform}` as ApiService' in page


def test_review_row_flags_executable_shortcut_email_and_unusual_url_examples():
    from app.services.artifact_review import review_row

    executable = review_row({
        "file_name": "invoice.pdf.exe",
        "file_path": "/Downloads/invoice.pdf.exe",
        "extension": ".exe",
        "metadata": {"double_extension": True},
    })
    shortcut = review_row({
        "file_name": "document.lnk",
        "file_path": "/Users/A/Recent/document.lnk",
        "extension": ".lnk",
        "metadata": {"target_path": "powershell.exe -enc AAA"},
    })
    email = review_row({
        "file_name": "message.eml",
        "file_path": "/Mail/message.eml",
        "extension": ".eml",
        "metadata": {"body": "attachment https://1.2.3.4/file"},
    })
    image = review_row(
        {
            "file_name": "photo.jpg",
            "file_path": "/DCIM/photo.jpg",
            "extension": ".jpg",
            "metadata": {},
        },
        content_text="Derived image description mentions a firearm on a table.",
    )

    assert {s["code"] for s in executable["signals"]} >= {"active_content", "double_extension"}
    assert {s["code"] for s in shortcut["signals"]} >= {"shortcut_execution", "command_execution"}
    assert {s["code"] for s in email["signals"]} >= {"email_content", "url_anomaly"}
    assert "media_content_review" in {s["code"] for s in image["signals"]}
