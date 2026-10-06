/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  readonly VITE_DEFAULT_TENANT?: string;
  readonly VITE_AETHERIS_SERVICE?: string;
  readonly VITE_VULN_MODULE_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
