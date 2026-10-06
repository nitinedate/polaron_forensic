import { Check } from "lucide-react";
import clsx from "clsx";

import { Card, PageHeader } from "../../components/ui";
import { useTheme, type ThemeDefinition } from "../../lib/theme";

function ThemePreview({ theme, selected }: { theme: ThemeDefinition; selected: boolean }) {
  return (
    <div
      className={clsx(
        "overflow-hidden rounded-xl border shadow-panel",
        selected ? "border-brand-400" : "border-ink-200"
      )}
      style={{ background: theme.preview.wash }}
    >
      <div className="flex h-28">
        <div className="flex w-[34%] flex-col border-r border-black/5 bg-white/80 px-2 py-2">
          <span className="mb-2 h-1.5 w-10 rounded-full" style={{ background: theme.preview.brand }} />
          <span className="mb-1 h-2 w-full rounded-md" style={{ background: `${theme.preview.brand}22` }} />
          <span className="mb-1 h-2 w-4/5 rounded-md bg-black/5" />
          <span className="h-2 w-3/5 rounded-md bg-black/5" />
        </div>
        <div className="flex-1 px-2 py-2">
          <div className="mb-2 h-4 rounded-md bg-white/90 shadow-panel" />
          <div className="h-14 rounded-md bg-white/80 p-2 shadow-panel">
            <span className="mb-1 block h-1.5 w-12 rounded-full" style={{ background: theme.preview.accent }} />
            <span className="block h-8 rounded-md" style={{ background: `${theme.preview.brand}18` }} />
          </div>
        </div>
      </div>
    </div>
  );
}

export function AppearancePage() {
  const { theme, setTheme, themes } = useTheme();

  return (
    <div>
      <PageHeader
        title="Appearance"
        subtitle="Choose a console theme. Polaron stays the default. Colors apply across the enterprise console and are saved on this browser."
      />
      <div className="grid gap-4 md:grid-cols-3">
        {themes.map((item) => {
          const selected = theme === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setTheme(item.id)}
              className="text-left"
            >
              <Card
                className={clsx(
                  "h-full p-4 transition ring-offset-2",
                  selected ? "ring-2 ring-brand-500" : "hover:border-brand-300"
                )}
              >
                <ThemePreview theme={item} selected={selected} />
                <div className="mt-4 flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-bold text-ink-900">
                      {item.name}
                      {item.isDefault ? (
                        <span className="ml-2 rounded-full bg-brand-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-brand-800">
                          Default
                        </span>
                      ) : null}
                    </p>
                    <p className="mt-1 text-xs text-ink-500">{item.tagline}</p>
                  </div>
                  {selected ? (
                    <span className="flex h-6 w-6 items-center justify-center rounded-full bg-brand-600 text-white">
                      <Check className="h-3.5 w-3.5" />
                    </span>
                  ) : (
                    <span className="h-6 w-6 rounded-full border border-ink-300" />
                  )}
                </div>
                <div className="mt-3">
                  <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-ink-400">
                    Chart palette
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {item.preview.chart.map((color) => (
                      <span
                        key={color}
                        className="h-3 w-8 rounded-full shadow-sm ring-1 ring-black/5"
                        style={{ background: color }}
                      />
                    ))}
                  </div>
                </div>
              </Card>
            </button>
          );
        })}
      </div>
    </div>
  );
}
