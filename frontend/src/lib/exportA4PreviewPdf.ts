import { A4_HEIGHT_MM, A4_PAGE_CLASS, A4_WIDTH_MM } from "./reportA4";

const A4_PT_W = 595.28;
const A4_PT_H = 841.89;
const PAGE_CAPTURE_MS = 40_000;
/** ~220 DPI on A4 CSS pixels (96 DPI). Text stays sharp instead of JPEG-soft. */
const SHARP_SCALES = [2.4, 2.0, 1.6];
const JPEG_QUALITY = 0.97;

function waitForPageImages(root: HTMLElement): Promise<void> {
  const images = Array.from(root.querySelectorAll("img"));
  return Promise.all(
    images.map(
      (img) =>
        new Promise<void>((resolve) => {
          if (img.complete) {
            resolve();
            return;
          }
          img.addEventListener("load", () => resolve(), { once: true });
          img.addEventListener("error", () => resolve(), { once: true });
        }),
    ),
  ).then(() => undefined);
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  window.setTimeout(() => {
    a.remove();
    URL.revokeObjectURL(url);
  }, 2_000);
}

export function previewPdfFilename(intake?: { organization?: string | null; subjects?: Array<{ name?: string | null }> | null } | null): string {
  const org = String(intake?.organization || "").trim();
  const subject = String(intake?.subjects?.[0]?.name || "").trim();
  const stem = [org, subject].filter(Boolean).join(" - ") || "Forensic Report";
  return `${stem.replace(/[\\/:*?"<>|]+/g, " ").replace(/\s+/g, " ").trim()} Forensic Report.pdf`;
}

type PdfImage = {
  data: Uint8Array;
  width: number;
  height: number;
  filter: "FlateDecode" | "DCTDecode";
};

function pagesToPdf(pages: PdfImage[]): Blob {
  if (!pages.length) {
    throw new Error("No report pages were captured.");
  }
  const enc = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let pos = 0;
  const offsets: number[] = [0];
  const push = (part: string | Uint8Array) => {
    const bytes = typeof part === "string" ? enc.encode(part) : part;
    chunks.push(bytes);
    pos += bytes.length;
  };
  const startObj = () => {
    offsets.push(pos);
  };

  push("%PDF-1.4\n");

  const pageObjNums: number[] = [];
  const body: Array<{ kind: "text"; text: string } | { kind: "bin"; text: string; data: Uint8Array }> = [];

  let next = 3;
  for (let i = 0; i < pages.length; i += 1) {
    const imageNo = next;
    const contentNo = next + 1;
    const pageNo = next + 2;
    next += 3;
    pageObjNums.push(pageNo);
    const page = pages[i];
    const content = `q ${A4_PT_W.toFixed(2)} 0 0 ${A4_PT_H.toFixed(2)} 0 0 cm /Im0 Do Q\n`;
    body.push({
      kind: "bin",
      text:
        `${imageNo} 0 obj\n<< /Type /XObject /Subtype /Image /Width ${page.width} /Height ${page.height} ` +
        `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /${page.filter} /Length ${page.data.length} >>\nstream\n`,
      data: page.data,
    });
    body.push({ kind: "text", text: `${contentNo} 0 obj\n<< /Length ${content.length} >>\nstream\n${content}endstream\nendobj\n` });
    body.push({
      kind: "text",
      text:
        `${pageNo} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${A4_PT_W} ${A4_PT_H}] ` +
        `/Resources << /XObject << /Im0 ${imageNo} 0 R >> >> /Contents ${contentNo} 0 R >>\nendobj\n`,
    });
  }

  startObj();
  push("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
  startObj();
  push(`2 0 obj\n<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(" ")}] /Count ${pages.length} >>\nendobj\n`);

  for (const item of body) {
    startObj();
    if (item.kind === "text") {
      push(item.text);
    } else {
      push(item.text);
      push(item.data);
      push("\nendstream\nendobj\n");
    }
  }

  const xrefPos = pos;
  push(`xref\n0 ${offsets.length}\n`);
  push("0000000000 65535 f \n");
  for (let i = 1; i < offsets.length; i += 1) {
    push(`${String(offsets[i]).padStart(10, "0")} 00000 n \n`);
  }
  push(`trailer\n<< /Size ${offsets.length} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`);

  const out = new Uint8Array(pos);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return new Blob([out], { type: "application/pdf" });
}

function neutralizeUnsupportedCss(root: HTMLElement): void {
  root.querySelectorAll<HTMLElement>("*").forEach((el) => {
    const style = el.getAttribute("style") || "";
    if (/oklch|oklab|color-mix|lab\(/i.test(style)) {
      el.style.color = "#111111";
      el.style.backgroundColor = "transparent";
      el.style.borderColor = "#111111";
    }
  });
}

function canvasToRgb(canvas: HTMLCanvasElement): Uint8Array {
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) throw new Error("Could not read a report page.");
  const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const rgb = new Uint8Array(width * height * 3);
  for (let i = 0, j = 0; i < data.length; i += 4) {
    rgb[j++] = data[i];
    rgb[j++] = data[i + 1];
    rgb[j++] = data[i + 2];
  }
  return rgb;
}

async function deflateBytes(bytes: Uint8Array): Promise<Uint8Array> {
  if (typeof CompressionStream === "undefined") {
    throw new Error("deflate unavailable");
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const stream = new Blob([copy]).stream().pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function canvasToJpeg(canvas: HTMLCanvasElement, quality: number): Promise<Uint8Array> {
  const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/jpeg", quality));
  if (blob) return new Uint8Array(await blob.arrayBuffer());
  const dataUrl = canvas.toDataURL("image/jpeg", quality);
  const comma = dataUrl.indexOf(",");
  if (comma < 0) throw new Error("Could not encode a report page.");
  const binary = atob(dataUrl.slice(comma + 1));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function canvasToPdfImage(canvas: HTMLCanvasElement): Promise<PdfImage> {
  try {
    const rgb = canvasToRgb(canvas);
    const deflated = await deflateBytes(rgb);
    if (deflated.length > 0 && deflated.length < rgb.length) {
      return { data: deflated, width: canvas.width, height: canvas.height, filter: "FlateDecode" };
    }
  } catch {
    /* JPEG still produces a usable page */
  }
  return {
    data: await canvasToJpeg(canvas, JPEG_QUALITY),
    width: canvas.width,
    height: canvas.height,
    filter: "DCTDecode",
  };
}

async function withTimeout<T>(work: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: number | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<T>((_, reject) => {
        timer = window.setTimeout(() => reject(new Error(label)), ms);
      }),
    ]);
  } finally {
    if (timer) window.clearTimeout(timer);
  }
}

async function capturePage(
  html2canvas: (typeof import("html2canvas"))["default"],
  el: HTMLElement,
  scale: number,
): Promise<PdfImage> {
  await waitForPageImages(el);
  const prev = {
    width: el.style.width,
    height: el.style.height,
    maxWidth: el.style.maxWidth,
    boxShadow: el.style.boxShadow,
    border: el.style.border,
    transform: el.style.transform,
  };
  el.scrollIntoView({ block: "nearest", inline: "nearest" });
  el.style.width = `${A4_WIDTH_MM}mm`;
  el.style.height = `${A4_HEIGHT_MM}mm`;
  el.style.maxWidth = "none";
  el.style.boxShadow = "none";
  el.style.border = "none";
  el.style.transform = "none";
  try {
    const canvas = await withTimeout(
      html2canvas(el, {
        scale,
        useCORS: true,
        allowTaint: true,
        backgroundColor: "#ffffff",
        logging: false,
        foreignObjectRendering: false,
        width: el.offsetWidth || undefined,
        height: el.offsetHeight || undefined,
        onclone: (doc) => {
          const cloned = doc.body;
          if (cloned) neutralizeUnsupportedCss(cloned);
        },
      }),
      PAGE_CAPTURE_MS,
      "A report page took too long to capture.",
    );
    return await canvasToPdfImage(canvas);
  } finally {
    el.style.width = prev.width;
    el.style.height = prev.height;
    el.style.maxWidth = prev.maxWidth;
    el.style.boxShadow = prev.boxShadow;
    el.style.border = prev.border;
    el.style.transform = prev.transform;
  }
}

export type PreviewPdfProgress = { page: number; total: number };

/** Capture every on-screen A4 sheet so the PDF matches the UI page structure. */
export async function captureA4PreviewPdf(
  onProgress?: (progress: PreviewPdfProgress) => void,
): Promise<Blob> {
  const pages = Array.from(document.querySelectorAll<HTMLElement>(`.${A4_PAGE_CLASS}`));
  if (!pages.length) {
    throw new Error("The report preview is not on screen. Open the report editor, then download PDF.");
  }

  const html2canvas = (await import("html2canvas")).default;
  const captured: PdfImage[] = [];

  for (let i = 0; i < pages.length; i += 1) {
    onProgress?.({ page: i + 1, total: pages.length });
    let page: PdfImage | null = null;
    let lastErr: unknown;
    for (const scale of SHARP_SCALES) {
      try {
        page = await capturePage(html2canvas, pages[i], scale);
        break;
      } catch (err) {
        lastErr = err;
      }
    }
    if (!page) {
      throw lastErr instanceof Error ? lastErr : new Error("A report page could not be captured.");
    }
    captured.push(page);
    await new Promise((resolve) => window.setTimeout(resolve, 20));
  }

  return pagesToPdf(captured);
}

export function savePreviewPdf(blob: Blob, filename: string): void {
  if (!blob.size) {
    throw new Error("The captured PDF was empty.");
  }
  downloadBlob(blob, filename);
}
