export type AetherisService =
  | "forensic"
  | "mobile-android"
  | "mobile-ios"
  | "mobile-extract"
  | "vuln"
  | "unified";

function normalize(raw: string | undefined): AetherisService {
  const value = String(raw || "unified").trim().toLowerCase();
  if (value === "unified" || value === "all" || value === "gateway") return "unified";
  if (["mobile-android", "mobile_android", "android-mobile", "android"].includes(value)) {
    return "mobile-android";
  }
  if (["mobile-ios", "mobile_ios", "ios-mobile", "ios"].includes(value)) return "mobile-ios";
  if (value === "mobile-extract" || value === "mobile_extract" || value === "mobile") {
    return "mobile-extract";
  }
  if (value === "vuln" || value === "vulnerabilities" || value === "vulnerability") return "vuln";
  if (value === "forensic") return "forensic";
  return "unified";
}

export function aetherisService(): AetherisService {
  return normalize(import.meta.env.VITE_AETHERIS_SERVICE as string | undefined);
}

export function isUnifiedService(): boolean {
  return aetherisService() === "unified";
}

export function isForensicService(): boolean {
  const mode = aetherisService();
  return mode === "forensic" || mode === "unified";
}

export function isMobileAndroidService(): boolean {
  return aetherisService() === "mobile-android";
}

export function isMobileIosService(): boolean {
  return aetherisService() === "mobile-ios";
}

export function isLegacyMobileExtractService(): boolean {
  return aetherisService() === "mobile-extract";
}

/** True for every mobile product.  Android/iOS remain separate identities. */
export function isMobileExtractService(): boolean {
  const mode = aetherisService();
  return mode === "mobile-android" || mode === "mobile-ios" || mode === "mobile-extract" || mode === "unified";
}

function mobilePlatformFromRoute(pathname?: string): "android" | "ios" | null {
  const route = String(
    pathname ?? (typeof window !== "undefined" ? window.location.pathname : "")
  ).toLowerCase();
  if (route.startsWith("/mobile/android") || route.startsWith("/android-mobile")) return "android";
  if (route.startsWith("/mobile/ios") || route.startsWith("/ios-mobile")) return "ios";
  return null;
}

export function mobilePlatformService(): "android" | "ios" | null {
  const mode = aetherisService();
  if (mode === "mobile-android") return "android";
  if (mode === "mobile-ios") return "ios";
  if (mode === "unified") return mobilePlatformFromRoute();
  return null;
}

/** UI route root for one isolated mobile platform. Dedicated products keep /mobile;
 *  the Enterprise Console pins the platform in the URL so backend routing is explicit. */
export function mobileUiBasePath(platform?: "android" | "ios" | null): string {
  const resolved = platform ?? mobilePlatformService();
  if (aetherisService() === "unified" && resolved) return `/mobile/${resolved}`;
  return "/mobile";
}

export function isDedicatedMobileService(): boolean {
  const mode = aetherisService();
  return mode === "mobile-android" || mode === "mobile-ios";
}

export function isVulnService(): boolean {
  const mode = aetherisService();
  return mode === "vuln" || mode === "unified";
}

export function serviceProductTitle(): string {
  switch (aetherisService()) {
    case "mobile-android":
      return "Android Forensics";
    case "mobile-ios":
      return "iOS Forensics";
    case "mobile-extract":
      return "Mobile Extraction (Legacy)";
    case "vuln":
      return "Vulnerability Operations";
    case "unified":
      return "Polaron";
    default:
      return "Disk Forensics";
  }
}
