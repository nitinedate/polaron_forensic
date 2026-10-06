/** ISO A4 — shared by on-screen preview and print/export. */
export const A4_WIDTH_MM = 210;
export const A4_HEIGHT_MM = 297;

/** Letterhead bands as a fraction of the A4 sheet (44mm header, 26mm footer). */
export const A4_LETTERHEAD_HEADER_MM = 44;
export const A4_LETTERHEAD_FOOTER_MM = 26;
export const A4_LETTERHEAD_HEADER_RATIO = A4_LETTERHEAD_HEADER_MM / A4_HEIGHT_MM;
export const A4_LETTERHEAD_FOOTER_RATIO = A4_LETTERHEAD_FOOTER_MM / A4_HEIGHT_MM;

export const A4_MARGIN_RIGHT_MM = 16;
export const A4_MARGIN_LEFT_MM = 16;

export const A4_PAGE_CLASS = "report-a4-page";
export const REPORT_HEADER_SRC = "/report/letterhead-header.png";
export const REPORT_FOOTER_SRC = "/report/letterhead-footer.png";

export const a4PageStyle = {
  width: `${A4_WIDTH_MM}mm`,
  aspectRatio: `${A4_WIDTH_MM} / ${A4_HEIGHT_MM}`,
  maxWidth: "100%",
  boxSizing: "border-box" as const,
};
