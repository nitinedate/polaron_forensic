# Report page-space compaction fix — 2026-09-16

## Problem reproduced
The report preview could place Operating System table rows 1-8 on one A4 page and move rows 9-10 to a new `(CONTINUED)` page even though a large unused area remained above the footer.

## Root cause
`frontend/src/lib/reportPagination.ts::tableRowUnits()` charged a minimum of **2 layout units to every table row**, even when a row rendered on a single physical line. With the section/table heading overhead this exhausted the synthetic 26-unit A4 body budget too early. The DOM then showed a visually half-empty page although the paginator believed the page was full.

## Fix
* Compact one-line table rows now cost 1 unit.
* Two-line rows cost 2 units.
* Rows that genuinely wrap to 3+ lines receive one additional safety unit.
* Long URL rows therefore remain conservative and still move whole to the next page when needed.
* The existing no-row-split and serial-number continuity protections remain unchanged.
* Report Generator Agent policy now explicitly requires rendered-height-aware table packing and forbids continuation pages while the next whole row can fit in the remaining A4 body.

## Regression simulation
Using the 10-row Operating System table shown by the user:
* row costs: `[2,1,1,1,1,1,1,1,1,1]`
* table heading/header cost: 5 units
* conservative narrative allowance: 4 units
* total: 20 units
* A4 body budget: 26 units

The full rows 1-10 therefore fit on the same report page; rows 9-10 no longer require an otherwise mostly-empty continuation page.

A long URL row still costs more than a compact row (test sample: 7 units vs 1), preserving the prior fix that prevents clipped/skipped annexure rows.

## Validation
* Standalone TypeScript compile of `reportPagination.ts`: PASS.
* Pagination simulation for the 10-row OS table: PASS (20 <= 26 units).
* Long-URL safety regression: PASS (tall row > compact row).
* Backend Report Generator Agent suite: `15 passed`.

No PostgreSQL schema migration is required.
