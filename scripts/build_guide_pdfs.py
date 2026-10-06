"""Build white-background operator PDFs with UI screenshots and flowcharts.

Each figure is sized to fit one A4 content box so images are never clipped
across a page break.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image
from weasyprint import HTML

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ROOT / "docs" / "guides"
UI = GUIDES / "assets" / "ui"
FLOW = GUIDES / "assets" / "flow"
OUT = GUIDES / "pdf"

# A4 210x297mm minus 16/14/18/14 margins ≈ 182 x 263mm.
# Leave room for the section heading + caption on the same page.
CONTENT_W_MM = 180.0
MAX_H_SHOT_MM = 165.0
MAX_H_FLOW_MM = 200.0

CSS = """
@page { size: A4; margin: 16mm 14mm 18mm 14mm; background: #ffffff; }
html, body {
  background: #ffffff !important;
  color: #141a23;
  font-family: "Segoe UI", Calibri, Arial, sans-serif;
  font-size: 10.5pt;
  line-height: 1.45;
}
h1 { font-size: 20pt; color: #141a23; margin: 0 0 8pt; }
h2 { font-size: 13pt; color: #3d2f16; margin: 14pt 0 6pt; border-bottom: 2px solid #c8a34a; padding-bottom: 3pt; }
h3 { font-size: 11pt; color: #424c5e; margin: 12pt 0 4pt; }
p, li { margin: 0 0 6pt; }
.sub { color: #505d74; font-size: 10pt; margin-bottom: 12pt; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0 12pt; font-size: 9.5pt; }
th, td { border: 1px solid #d5dae2; padding: 5pt 6pt; text-align: left; vertical-align: top; }
th { background: #fbf7ec; }
figure.shot, figure.flow {
  margin: 8pt 0 12pt;
  text-align: center;
  break-inside: avoid;
  page-break-inside: avoid;
}
figure img {
  display: block;
  margin: 0 auto;
  background: #ffffff;
  max-width: 100%;
}
figure.shot img { border: 1px solid #eceef2; }
.cap { font-size: 8.5pt; color: #65748d; margin-top: 4pt; text-align: center; }
.rules { background: #fbf7ec; border: 1px solid #ecd99a; padding: 8pt 10pt; break-inside: avoid; }
.brand { color: #a9852f; font-size: 9pt; letter-spacing: 0.08em; text-transform: uppercase; }
.flow-block { break-inside: avoid; page-break-inside: avoid; break-before: page; page-break-before: always; }
.flow-block h2 { margin-top: 0; }
"""


def _fit_mm(path: Path, max_h_mm: float) -> tuple[float, float]:
    with Image.open(path) as im:
        w_px, h_px = im.size
    scale = min(CONTENT_W_MM / w_px, max_h_mm / h_px)
    return round(w_px * scale, 1), round(h_px * scale, 1)


def figure(path: Path, caption: str, kind: str) -> str:
    if not path.exists():
        return f"<p class='cap'>[Image not captured: {path.name}]</p>"
    max_h = MAX_H_FLOW_MM if kind == "flow" else MAX_H_SHOT_MM
    width_mm, height_mm = _fit_mm(path, max_h)
    uri = path.resolve().as_uri()
    return (
        f"<figure class='{kind}'>"
        f"<img src='{uri}' alt='{caption}' style='width:{width_mm}mm;height:{height_mm}mm'/>"
        f"<figcaption class='cap'>{caption}</figcaption>"
        f"</figure>"
    )


def flow(name: str, caption: str, heading: str, intro: str = "") -> str:
    extra = f"<p>{intro}</p>" if intro else ""
    return (
        f"<div class='flow-block'><h2>{heading}</h2>{extra}"
        f"{figure(FLOW / f'{name}.png', caption, 'flow')}</div>"
    )


def ui(name: str, caption: str) -> str:
    return figure(UI / f"{name}.png", caption, "shot")


def write_pdf(name: str, title: str, body: str) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    html = f"""<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>
    <style>{CSS}</style></head>
    <body>
    <div class='brand'>Aetheris Technologies · Operator guide</div>
    <h1>{title}</h1>
    {body}
    </body></html>"""
    dest = OUT / name
    HTML(string=html, base_url=str(GUIDES)).write_pdf(dest)
    return dest


def forensic() -> Path:
    body = f"""
    <p class='sub'>Analyze disk images (E01 and similar) or an already-imported mobile image.
    Console: http://localhost:3000. Not for live phone pull — see guide 02.</p>

    <h2>Login</h2>
    <p>Organization (firm slug) → Email → Password sign-in, or Send token / Access token → Continue.</p>
    {ui("login", "Login — access token (default)")}
    {ui("login-password", "Login — Password sign-in expanded")}

    <h2>Open Forensic</h2>
    <p>Sidebar <b>Forensic</b>: Disk Jobs, Image evidence, Report list, Search evidence.</p>
    {ui("dashboard", "Dashboard after firm login")}
    {ui("jobs-list", "Forensic jobs — Select folder & start, New job")}
    {ui("job-new", "New forensic job — Job type, Case ID, Create job")}
    {ui("image-evidence", "Image evidence — upload from this computer or Add server path")}

    <h2>Server location vs client PC</h2>
    <table>
      <tr><th></th><th>Server / examiner workstation</th><th>Client PC (browser only)</th></tr>
      <tr><td>Evidence</td><td>USB / E:\\ / Docker-mounted drive on the Docker host</td><td>Folder on this laptop; server cannot see the disk</td></tr>
      <tr><td>UI</td><td>Job detail → Folder browser (This PC, Refresh drive mounts, Start HostDrive agent)</td><td>Select disk folder… / Browse folder… → Choose folder… → Use selected</td></tr>
      <tr><td>How files move</td><td>Register in place — E01 is not copied first</td><td>Helper tries register-in-place; else browser upload</td></tr>
      <tr><td>Image evidence</td><td>Add server path · Add current folder</td><td>Choose files / Choose folder / drag-drop</td></tr>
    </table>
    {ui("job-detail", "Job detail — evidence panel and Processing pipeline (14 agents)")}

    <h2>Job detail UI</h2>
    <p>Cards: Status, Progress, Created, Case. Evidence: Disk image | Mobile extraction | iOS backup | Android backup.</p>
    <p>Agents: List folder → Get segments → Virtual disk → Extraction → Materialize → OCR enrich →
    Parse forensic files → RAG chunking → RAG embedding → Entity extraction → Neo4j graph →
    Annotation → Ontology → Artifact inventory.</p>
    {ui("job-artifacts-select", "Artifact selection")}
    {ui("job-intake", "Case intake — required before report")}
    {ui("job-report", "Report editor")}
    {ui("reports", "Report list")}
    {ui("evidence-search", "Search evidence")}

    {flow("forensic-server", "Disk / mobile forensic — evidence on the server / examiner workstation", "Flow — server location")}
    {flow("forensic-client", "Disk / mobile forensic — evidence on the client PC", "Flow — client location")}

    <div class='rules'>
    <b>Rules.</b> Same machine as Docker + mounted drive → Folder browser (server).
    Remote browser → Choose folder; upload if register-in-place fails.
    Report stays blocked until Case intake is filled.
    </div>
    """
    return write_pdf("01-disk-mobile-forensic.pdf", "1. Disk & mobile forensic (analysis)", body)


def mobile() -> Path:
    body = f"""
    <p class='sub'>Import a UFED-style package or live-acquire a USB device.
    After the working image exists, use guide 01 for the 14-agent analysis.</p>

    <h2>Open</h2>
    <p>Sidebar <b>Mobile Extraction</b>: Extractions, Import package, Live acquire.</p>
    {ui("login", "Login — access token")}
    {ui("login-password", "Login — Password sign-in")}
    {ui("mobile-list", "Mobile Extraction list — New mobile extraction")}
    {ui("mobile-new", "New mobile extraction — Mobile OS, legal ack, Create & add extraction")}
    {ui("mobile-acquire", "Acquire from device — Connect → Identify → Authorise → Collect → Complete")}

    <h2>Server location vs client PC</h2>
    <table>
      <tr><th></th><th>Server / examiner workstation</th><th>Client PC</th></tr>
      <tr><td>Package on disk</td><td>Folder Docker can mount → Folder browser</td><td>Select existing extraction folder — browser uploads .pas / .ufd / .ufdx / .zip</td></tr>
      <tr><td>Live phone</td><td>USB into this PC + HostDrive helper</td><td>Same — cable must be on the helper PC, not a remote server</td></tr>
    </table>
    {ui("job-detail", "Job detail after create — Upload or select mobile extraction")}

    {flow("mobile-server", "Import package from a server-visible folder", "Flow — server import")}
    {flow("mobile-client", "Import package from a client browser (upload)", "Flow — client import")}
    {flow("mobile-live", "Live acquire — device must be plugged into the examiner PC", "Flow — live USB")}

    <div class='rules'>
    <b>Rules.</b> Import = package exists. Acquire = phone on USB now.
    Client import does not need a server disk mount.
    </div>
    """
    return write_pdf("02-mobile-extraction.pdf", "2. Mobile extraction", body)


def vuln() -> Path:
    body = f"""
    <p class='sub'>Launch scans in the central UI. OpenVAS runs on the server (Central GMP).
    A browser scanner token authorizes one client CIDR — nothing is installed on the client PC.</p>

    <h2>Open</h2>
    <p>Login to a <b>firm</b> tenant (not platform). Dashboard Vulnerability management, or sidebar Vuln Dashboards / Vuln Operations.</p>
    {ui("login", "Login — firm tenant")}
    {ui("login-password", "Password sign-in")}
    {ui("dashboard", "Dashboard — Vulnerability management hubs")}
    {ui("vuln-dashboards", "Vulnerability Dashboards — layers and filters")}
    {ui("vuln-ops", "Vulnerability Functionality — ops tiles and pre-scan banner")}

    <h2>Server-side scan (central)</h2>
    <p>Add scanner role <b>Central GMP</b> or <b>Managed Remote / VPN</b>. Optional Policies and Credentials.
    Scan jobs → Case → Launch scan. Confirm pre-scan checkbox.</p>
    {ui("vuln-scanners", "Scanners")}
    {ui("vuln-add-scanner", "Add scanner modal")}
    {ui("vuln-policies", "Scan policies")}
    {ui("vuln-new-policy", "New policy modal")}
    {ui("vuln-credentials", "Scan credentials — vault refs only")}
    {ui("vuln-scans", "Scan jobs")}
    {ui("vuln-new-case", "New case")}
    {ui("vuln-launch-scan", "Launch scan — targets, authorization, pre-scan")}

    {flow("vuln-server", "Central / server scan flow", "Flow — server (central GMP)")}

    {flow(
        "vuln-client",
        "Client network token flow",
        "Flow — client (browser scanner token)",
        "Scanners → Request network token (CIDR) → copy the scanner token → Connect client network and paste it. "
        "Launch scan is locked to Central GMP. Only IPs inside that CIDR are accepted. "
        "The server must be able to reach those hosts. Do not run Start-Laptop.cmd.",
    )}

    <h2>After any scan</h2>
    {ui("vuln-findings", "Vulnerability explorer")}
    {ui("vuln-remediation", "Remediation board")}
    {ui("vuln-exceptions", "Exception governance")}
    {ui("vuln-timeline", "Unified timeline")}
    {ui("vuln-reports", "Reports & export")}
    {ui("vuln-risk", "Risk dashboard")}
    {ui("vuln-agents", "Nessus agents — not the laptop OpenVAS agent")}

    <div class='rules'>
    <b>Rules.</b> Always launch from Scan jobs. Packets fire from the server.
    Client sites use a network scanner token (CIDR allow-list) pasted in the browser.
    Pre-scan checkbox is required. The server cannot see a remote private LAN unless those IPs are already reachable.
    </div>
    """
    return write_pdf("03-vuln-scanning.pdf", "3. Vulnerability scanning", body)


if __name__ == "__main__":
    paths = [forensic(), mobile(), vuln()]
    for p in paths:
        print(p)
