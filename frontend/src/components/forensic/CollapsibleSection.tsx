import clsx from "clsx";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { ReactNode } from "react";

interface CollapsibleSectionProps {
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  defaultOpen?: boolean;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
  className?: string;
}

export function CollapsibleSection({
  title,
  subtitle,
  badge,
  open,
  onToggle,
  children,
  className,
}: CollapsibleSectionProps) {
  return (
    <div className={clsx("overflow-hidden rounded-lg border border-ink-100 bg-white", className)}>
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center gap-2 border-b border-ink-100 px-4 py-3 text-left hover:bg-ink-50/60"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-ink-400" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-ink-400" />
        )}
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-ink-800">{title}</p>
          {subtitle ? <p className="text-xs text-ink-500">{subtitle}</p> : null}
        </div>
        {badge}
      </button>
      {open ? <div className="min-h-0">{children}</div> : null}
    </div>
  );
}
