from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_unified_sidebar_exposes_mobile_forensics_workflows():
    layout = read("frontend/src/components/AppLayout.tsx")
    assert 'title: "Mobile Forensics"' in layout
    for route, label in (
        ('/mobile', 'Mobile Overview'),
        ('/mobile/acquisition', 'Device → Image'),
        ('/mobile/images', 'Images → RAG'),
        ('/mobile/jobs', 'Mobile Jobs'),
        ('/mobile/rag', 'Mobile RAG'),
        ('/mobile/reports', 'Mobile Reports'),
    ):
        assert f'to: "{route}"' in layout
        assert f'label: "{label}"' in layout
    assert "isUnifiedService()" in layout


def test_unified_routes_pin_android_and_ios_in_the_url():
    app = read("frontend/src/App.tsx")
    for route in (
        'mobile/android',
        'mobile/android/new',
        'mobile/android/acquire',
        'mobile/android/jobs/:jobId',
        'mobile/android/jobs/:jobId/report',
        'mobile/ios',
        'mobile/ios/new',
        'mobile/ios/acquire',
        'mobile/ios/jobs/:jobId',
        'mobile/ios/jobs/:jobId/report',
    ):
        assert f'path="{route}"' in app
    assert "<MobileOverviewPage />" in app
    assert "<MobileImageProcessingPage />" in app
    assert "<MobileRagDirectoryPage />" in app
    assert "<MobileReportsDirectoryPage />" in app


def test_gateway_header_selection_understands_unified_mobile_routes():
    routing = read("frontend/src/lib/apiRouting.ts")
    assert 'route.startsWith("/mobile/android")' in routing
    assert 'return "mobile-android"' in routing
    assert 'route.startsWith("/mobile/ios")' in routing
    assert 'return "mobile-ios"' in routing
    assert 'export function alternateJobService(_service: ApiService): ApiService | null { return null; }' in routing


def test_mobile_platform_can_be_inferred_from_unified_route_without_becoming_dedicated_mode():
    mode = read("frontend/src/lib/serviceMode.ts")
    assert 'route.startsWith("/mobile/android")' in mode
    assert 'route.startsWith("/mobile/ios")' in mode
    assert 'if (mode === "unified") return mobilePlatformFromRoute();' in mode
    assert 'return mode === "mobile-android" || mode === "mobile-ios";' in mode


def test_direct_host_helper_devices_are_filtered_to_current_mobile_platform():
    page = read("frontend/src/pages/forensic/MobileAcquisitionPage.tsx")
    assert 'const fixedPlatform = mobilePlatformService();' in page
    assert 'const devicesNow = [...mergedDevices.values()].filter((device) =>' in page
    assert 'String(device.os_family || "").toLowerCase().includes(fixedPlatform)' in page
    assert 'const adaptersNow = [...merged.values()].filter((adapter) =>' in page


def test_mobile_console_does_not_link_to_disk_job_routes():
    mobile = read("frontend/src/pages/mobile/MobileConsolePages.tsx")
    assert "/forensic/jobs" not in mobile
    assert "/forensic/reports" not in mobile
    assert 'service: platformService(platform)' in mobile
    assert 'mobileUiBasePath(entry.platform)' in mobile


def test_unified_dashboard_reads_both_isolated_mobile_backends():
    dashboard = read("frontend/src/pages/Dashboard.tsx")
    assert 'isUnifiedService()' in dashboard
    assert 'service: "mobile-android"' in dashboard
    assert 'service: "mobile-ios"' in dashboard
    assert 'Android + iOS isolated APIs' in dashboard


def test_job_directory_pins_listed_jobs_to_their_backend():
    api = read("frontend/src/lib/forensicApi.ts")
    assert 'for (const job of result.items ?? []) rememberJobService(job.id, service);' in api
