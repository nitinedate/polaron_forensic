# Polaron V29 — Theme-aware donut charts

## Goal
Make donut/radial analytics more attractive and prevent generic categories from collapsing to the same fallback color, while keeping colors aligned with the active console theme.

## What changed

### Theme-aware chart palettes
All three console themes now define a 10-color analytics palette plus semantic chart colors:

- **Polaron** — saffron/green with indigo, sky, violet, rose, teal and amber accents.
- **Harbor** — teal/indigo with sky, emerald, amber, pink, violet, cyan and lime accents.
- **Midnight** — indigo/gold with violet, cyan, emerald, rose, orange, blue and fuchsia accents.

Changing the theme in **Settings → Appearance** updates chart colors automatically.

### Generic category fix
Previously, `countBy()` assigned the status fallback color to every unknown category. That meant arbitrary values such as plans, source names, role names, or other category labels could all become the same orange.

V29 only assigns a forced color when the label is a known semantic status/severity. Generic categories are left uncolored so the chart component assigns distinct colors from the active theme palette.

### Donut presentation
- Up to 10 distinct categorical colors are available before cycling.
- Donut slices use small rounded corners and clean separators.
- A deterministic palette offset is derived from the chart key/title so separate categorical donuts do not all begin with exactly the same hue order.
- Existing semantic states stay recognizable: success/complete, warning/pending, processing, failure, and vulnerability severities retain meaningful color families while adapting slightly per theme.

### Vulnerability donut
The custom vulnerability severity donut now uses the same theme-aware semantic tokens for critical/high/medium/low/info instead of hard-coded hex values.

### Radial gauges
Radial gauges and progress rings now use the same theme semantic colors and theme track color, keeping the full analytics surface visually consistent.

### Appearance preview
Each theme card on **Settings → Appearance** now shows its chart palette, so users can see the analytics color family before choosing the theme.

## Regression protection
Added `backend/tests/test_theme_aware_donuts_v29.py` covering:

1. palette variables for all three themes;
2. removal of the one-color generic-category fallback;
3. theme-aware donut palette/rounded slices;
4. semantic vulnerability/status colors;
5. chart-palette previews on the Appearance page.

## Validation
- V29 theme/donut tests: **5 passed**
- V29 + V28 artifact workflow regression subset: **18 passed**
- Changed TypeScript/TSX files: syntax transpilation passed with TypeScript 5.8.3.
- CSS palette token completeness check passed for all three themes.

No backend processing, semaphore, Disk/Mobile evidence, RAG, OCR, upload, or LaptopScanner behavior is changed by V29.
