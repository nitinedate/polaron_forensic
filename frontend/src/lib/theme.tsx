import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export const THEME_STORAGE_KEY = "polaron-theme";

export type ThemeId = "polaron" | "harbor" | "midnight";

export type ThemeDefinition = {
  id: ThemeId;
  name: string;
  tagline: string;
  preview: { brand: string; accent: string; wash: string; chart: string[] };
  isDefault?: boolean;
};

export const THEMES: ThemeDefinition[] = [
  {
    id: "polaron",
    name: "Polaron",
    tagline: "Saffron and green — the current console",
    preview: {
      brand: "#f47b20",
      accent: "#138808",
      wash: "#fff8f1",
      chart: ["#f47b20", "#138808", "#4f46e5", "#0ea5e9", "#a855f7", "#e11d48"],
    },
    isDefault: true,
  },
  {
    id: "harbor",
    name: "Harbor",
    tagline: "Teal laboratory — calm, precise, forensic",
    preview: {
      brand: "#0d9488",
      accent: "#4338ca",
      wash: "#f0fdfa",
      chart: ["#0d9488", "#4f46e5", "#0ea5e9", "#10b981", "#d97706", "#db2777"],
    },
  },
  {
    id: "midnight",
    name: "Midnight",
    tagline: "Indigo and gold — evening courtroom",
    preview: {
      brand: "#4f46e5",
      accent: "#d9911e",
      wash: "#eef2ff",
      chart: ["#4f46e5", "#d9911e", "#8b5cf6", "#06b6d4", "#10b981", "#f43f5e"],
    },
  },
];

const THEME_IDS = new Set<string>(THEMES.map((theme) => theme.id));

export function isThemeId(value: string | null | undefined): value is ThemeId {
  return Boolean(value && THEME_IDS.has(value));
}

export function readStoredTheme(): ThemeId {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (isThemeId(raw)) return raw;
  } catch {
    /* private mode */
  }
  return "polaron";
}

export function applyThemeToDocument(theme: ThemeId): void {
  const root = document.documentElement;
  if (theme === "polaron") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

type ThemeContextValue = {
  theme: ThemeId;
  setTheme: (theme: ThemeId) => void;
  themes: ThemeDefinition[];
};

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeId>(() =>
    typeof document === "undefined" ? "polaron" : readStoredTheme()
  );

  useEffect(() => {
    applyThemeToDocument(theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      /* ignore quota */
    }
  }, [theme]);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      setTheme: setThemeState,
      themes: THEMES,
    }),
    [theme]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return ctx;
}
