import { useState } from "react";
import clsx from "clsx";

/**
 * Sidebar brand: Polararon logo (transparent PNG) scaled to fit the
 * header slot. Falls back to a monogram only if /public/logo.png is missing.
 */
export function Brand({ compact = false, className }: { compact?: boolean; className?: string }) {
  const [broken, setBroken] = useState(false);

  if (!broken) {
    return (
      <div
        className={clsx(
          "flex w-full flex-col items-center justify-center overflow-hidden bg-transparent",
          compact ? "px-1 py-0.5" : "px-1 py-1",
          className
        )}
      >
        <img
          src="/logo.png"
          alt="Polaron Technologies"
          onError={() => setBroken(true)}
          className={clsx(
            "block w-full object-contain object-center",
            compact ? "max-h-8" : "max-h-[5.25rem]"
          )}
        />
        {!compact && (
          <div className="mt-2 flex h-0.5 w-full overflow-hidden rounded-full" aria-hidden>
            <span className="h-full flex-[2] bg-brand-500" />
            <span className="h-full w-5 bg-white" />
            <span className="h-full flex-[2] bg-accent-600" />
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={clsx("flex items-center gap-3", className)}>
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-brand-400 to-brand-700 font-extrabold text-white shadow">
        P
      </div>
      {!compact && (
        <div className="leading-tight">
          <div className="text-sm font-extrabold tracking-wide text-ink-900">POLARON</div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-accent-700">
            Technologies
          </div>
        </div>
      )}
    </div>
  );
}
