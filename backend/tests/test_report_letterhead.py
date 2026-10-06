from io import BytesIO
from pathlib import Path

from PIL import Image

from app.services.report_letterhead import (
    apply_forensic_letterhead,
    flatten_letterhead_band,
    white_letterhead_png,
)


def test_letterhead_assets_exist():
    root = Path(__file__).resolve().parents[1] / "app" / "static" / "report"
    for name in (
        "letterhead-header.png",
        "letterhead-footer.png",
        "watermark.png",
        "confidential-stamp.png",
    ):
        assert (root / name).is_file(), name


def test_apply_letterhead_keeps_valid_pdf():
    try:
        import fitz
    except ImportError:
        return
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((72, 400), "CYBER FORENSIC ANALYSIS REPORT")
    raw = doc.tobytes()
    doc.close()
    stamped = apply_forensic_letterhead(raw)
    assert stamped.startswith(b"%PDF")
    assert len(stamped) > len(raw)
    stamped_doc = fitz.open(stream=stamped, filetype="pdf")
    assert "Page 1" in stamped_doc[0].get_text()
    stamped_doc.close()


def test_flatten_letterhead_band_paints_gray_chrome_white():
    gray = Image.new("RGB", (80, 40), (237, 237, 237))
    for x in range(20, 60):
        for y in range(8, 32):
            gray.putpixel((x, y), (245, 120, 40))
    out = flatten_letterhead_band(gray)
    pixels = [out.getpixel((x, y)) for y in range(out.size[1]) for x in range(out.size[0])]
    assert out.size[0] < 80
    assert (237, 237, 237) not in pixels
    assert out.getpixel((out.size[0] // 2, out.size[1] // 2)) == (245, 120, 40)


def test_letterhead_assets_have_white_paper():
    root = Path(__file__).resolve().parents[1] / "app" / "static" / "report"
    for name in ("letterhead-header.png", "letterhead-footer.png"):
        raw = (root / name).read_bytes()
        flattened = Image.open(BytesIO(white_letterhead_png(raw))).convert("RGB")
        width, height = flattened.size
        for x, y in ((0, 0), (width - 1, 0), (0, height - 1), (width - 1, height - 1)):
            red, green, blue = flattened.getpixel((x, y))
            chroma = max(red, green, blue) - min(red, green, blue)
            if chroma < 14:
                assert min(red, green, blue) >= 250, (name, x, y, (red, green, blue))


def test_white_letterhead_png_keeps_safe_left_and_right_margins():
    root = Path(__file__).resolve().parents[1] / "app" / "static" / "report"
    for name in ("letterhead-header.png", "letterhead-footer.png"):
        raw = (root / name).read_bytes()
        flattened = Image.open(BytesIO(white_letterhead_png(raw))).convert("RGB")
        width, height = flattened.size

        def non_white_in_col(x: int) -> int:
            return sum(
                1
                for y in range(height)
                if min(flattened.getpixel((x, y))) < 245
            )

        margin_scan = min(max(12, width // 30), width // 4)
        assert all(non_white_in_col(x) == 0 for x in range(margin_scan)), (name, "left", width)
        assert all(non_white_in_col(width - 1 - x) == 0 for x in range(margin_scan)), (name, "right", width)
