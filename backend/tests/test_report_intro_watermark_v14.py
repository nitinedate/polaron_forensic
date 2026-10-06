from pathlib import Path

from PIL import Image


def test_watermark_asset_is_baked_very_light_for_all_renderers():
    root = Path(__file__).resolve().parents[2]
    paths = [
        root / "backend" / "app" / "static" / "report" / "watermark.png",
        root / "frontend" / "public" / "report" / "watermark.png",
    ]
    for path in paths:
        image = Image.open(path).convert("RGBA")
        assert image.getchannel("A").getextrema()[1] <= 18, path


def test_backend_and_frontend_use_same_watermark_bytes():
    root = Path(__file__).resolve().parents[2]
    backend = root / "backend" / "app" / "static" / "report" / "watermark.png"
    frontend = root / "frontend" / "public" / "report" / "watermark.png"
    assert backend.read_bytes() == frontend.read_bytes()
