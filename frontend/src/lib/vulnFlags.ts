import { isVulnService } from "./serviceMode";

/** Vulnerability UI is on the unified gateway and on a vuln-only build. */
export function isVulnModuleEnabled(): boolean {
  if (!isVulnService()) return false;
  const v = (import.meta.env.VITE_VULN_MODULE_ENABLED as string | undefined) ?? "true";
  return !["0", "false", "no", "off"].includes(String(v).trim().toLowerCase());
}
