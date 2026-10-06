import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const API_BY_MODE: Record<string, string> = {
  forensic: "http://127.0.0.1:8083",
  "mobile-android": "http://127.0.0.1:8081",
  "mobile-ios": "http://127.0.0.1:8084",
  "mobile-extract": "http://127.0.0.1:8081",
  vuln: "http://127.0.0.1:8082",
  unified: "http://127.0.0.1:8083",
};

function gatewayTarget(req: { headers: Record<string, unknown>; url?: string }): string {
  const svc = String(req.headers["x-aetheris-service"] || "").toLowerCase();
  if (svc === "mobile-android" || svc === "android") return "http://127.0.0.1:8081";
  if (svc === "mobile-ios" || svc === "ios") return "http://127.0.0.1:8084";
  if (svc === "mobile-extract" || svc === "mobile") return "http://127.0.0.1:8081";
  if (svc === "vuln") return "http://127.0.0.1:8082";
  const url = req.url || "";
  if (
    url.startsWith("/api/vuln") || url.startsWith("/api/scanners") ||
    url.startsWith("/api/scanner-agent") || url.startsWith("/api/scan-jobs") ||
    url.startsWith("/api/scan-policies") || url.startsWith("/api/assets") ||
    url.startsWith("/api/remediation")
  ) return "http://127.0.0.1:8082";
  // Acquisition intentionally has no URL-only default. The UI must identify Android/iOS.
  return "http://127.0.0.1:8083";
}

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": {
        target: API_BY_MODE[mode] || "http://127.0.0.1:8083",
        changeOrigin: true,
        router: mode === "unified" || mode === "development" ? gatewayTarget : undefined,
      },
    },
  },
  preview: { host: true, port: 4173 },
}));
