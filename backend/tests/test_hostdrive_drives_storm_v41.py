from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_folder_dialog_does_not_restack_drive_listing_on_rerender():
    dialog = read("frontend/src/components/forensic/BrowseFolderDialog.tsx")
    assert "const NO_RECOMMENDED_LETTERS: string[] = []" in dialog
    assert "recommendedLetters = NO_RECOMMENDED_LETTERS" in dialog
    assert "recommendedLettersKey" in dialog
    assert "[open, recommendedLettersKey]" in dialog
    assert "justCameOnline" in dialog
    assert "if (open && helperOnline === true && windowsVolumes.length === 0)" not in dialog


def test_office_drive_listing_is_deduped_and_skips_api_when_helper_is_online():
    helper = read("frontend/src/lib/hostDriveHelper.ts")
    fn = helper.split("export async function listOfficeServerDriveLetters", 1)[1].split(
        "export async function listOfficeServerDirectory", 1
    )[0]
    assert "drivesListInFlight" in fn
    assert "DRIVES_LIST_CACHE_MS" in helper
    assert "helperOnline && isBrowserOnOfficeHost()" in fn
    assert 'hostDriveHelperHealth(Math.min(timeoutMs, 2000), { force: true })' not in helper.split(
        "async function listOfficeHostDriveLettersDirect", 1
    )[1].split("async function listOfficeHostDirectoryDirect", 1)[0]


def test_network_error_does_not_blame_vite_dev_proxy():
    api = read("frontend/src/lib/api.ts")
    assert "Vite dev proxy" not in api
    assert "Unable to reach the API at ${target}" in api
    compact = read("frontend/src/pages/mobile/MobileCompactJobPage.tsx")
    assert "async (silent = false)" in compact
    assert "void load(true)" in compact
