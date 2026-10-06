import clsx from "clsx";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from "react";
import { GripVertical, X } from "lucide-react";

import { useDraggablePanel } from "../hooks/useDraggablePanel";

type Variant = "primary" | "brand" | "ghost" | "outline" | "danger";

export function Button({
  variant = "primary",
  className,
  loading,
  children,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; loading?: boolean }) {
  const map: Record<Variant, string> = {
    primary: "btn-primary",
    brand: "btn-brand",
    ghost: "btn-ghost",
    outline: "btn-outline",
    danger: "btn-danger",
  };
  return (
    <button className={clsx(map[variant], className)} disabled={loading || rest.disabled} {...rest}>
      {loading && <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />}
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label?: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <div>
      {label && <label className="label text-sm font-semibold text-ink-800">{label}</label>}
      {children}
      {hint && !error && <p className="mt-1 text-sm text-ink-500">{hint}</p>}
      {error && <p className="mt-1 text-sm font-medium text-red-600">{error}</p>}
    </div>
  );
}

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={clsx("input", props.className)} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={clsx("input", props.className)} />;
}

export function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "green" | "amber" | "red" | "indigo";
}) {
  const tones: Record<string, string> = {
    neutral: "bg-ink-100 text-ink-600",
    green: "bg-accent-50 text-accent-800",
    amber: "bg-brand-50 text-brand-800",
    red: "bg-red-50 text-red-700",
    indigo: "bg-indigo-50 text-indigo-700",
  };
  return <span className={clsx("badge", tones[tone])}>{children}</span>;
}

export function PageHeader({
  title,
  subtitle,
  titleClassName,
  actions,
}: {
  title: string;
  subtitle?: string;
  titleClassName?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 className={clsx("text-2xl font-bold tracking-tight text-ink-900", titleClassName)}>{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-500">{subtitle}</p>}
        <div className="mt-2.5 h-0.5 w-14 overflow-hidden rounded-full" aria-hidden>
          <div className="flex h-full w-full">
            <span className="h-full flex-[2] bg-brand-500" />
            <span className="h-full w-2.5 bg-white" />
            <span className="h-full flex-[2] bg-accent-600" />
          </div>
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("card", className)}>{children}</div>;
}

/** Nested surface inside a card — very light brand-tinted fill. */
export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("panel", className)}>{children}</div>;
}

export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  size = "md",
  draggable = false,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  size?: "md" | "lg";
  draggable?: boolean;
}) {
  const { panelStyle, dragHandleProps } = useDraggablePanel(open);

  if (!open) return null;

  const panelClass = clsx(
    "relative z-10 w-full overflow-hidden rounded-2xl border border-ink-300 bg-gradient-to-b from-white to-brand-50/40 shadow-soft",
    size === "lg" ? "max-w-2xl" : "max-w-lg",
    draggable && "absolute left-1/2 top-1/2"
  );

  return (
    <div className={clsx("fixed inset-0 z-40", draggable ? "" : "flex items-center justify-center p-4")}>
      <div className="absolute inset-0 bg-ink-950/40 backdrop-blur-sm" onClick={onClose} />
      <div className={panelClass} style={draggable ? panelStyle : undefined}>
        <div
          {...(draggable ? dragHandleProps : {})}
          className={clsx(
            "flex items-center justify-between border-b border-ink-300 bg-brand-50/40 px-6 py-4",
            draggable && dragHandleProps.className
          )}
        >
          <div className="flex min-w-0 items-center gap-2">
            {draggable ? <GripVertical className="h-4 w-4 shrink-0 text-ink-300" aria-hidden /> : null}
            <h3 className="text-lg font-bold text-ink-900">{title}</h3>
          </div>
          <button
            data-no-drag
            onClick={onClose}
            className="rounded-xl p-1 text-ink-400 hover:bg-brand-50 hover:text-ink-600"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto bg-white/60 px-6 py-5">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 border-t border-ink-300 bg-brand-50/30 px-6 py-4">{footer}</div>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      <p className="text-sm font-semibold text-ink-700">{title}</p>
      {hint && <p className="mt-1 text-sm text-ink-400">{hint}</p>}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return (
    <div className={clsx("flex items-center justify-center py-16", className)}>
      <div className="h-8 w-8 animate-spin rounded-full border-4 border-ink-200 border-t-brand-500" />
    </div>
  );
}

/** Keep page chrome visible. Only the data region waits, and a blocked API can retry. */
export function LoadPanel({
  loading,
  error,
  hasData,
  onRetry,
  empty,
  children,
}: {
  loading: boolean;
  error?: string | null;
  hasData: boolean;
  onRetry?: () => void;
  empty?: ReactNode;
  children: ReactNode;
}) {
  if (hasData) {
    return (
      <div className="relative">
        {loading ? (
          <div
            className="absolute right-3 top-3 z-10 h-4 w-4 animate-spin rounded-full border-2 border-ink-200 border-t-brand-500"
            aria-label="Refreshing"
          />
        ) : null}
        {children}
      </div>
    );
  }
  if (loading) return <Spinner />;
  if (error) {
    return (
      <div className="px-5 py-12 text-center">
        <p className="text-sm font-semibold text-ink-700">This page is ready — data is still catching up.</p>
        <p className="mx-auto mt-2 max-w-xl text-sm text-ink-500">{error}</p>
        {onRetry ? (
          <Button className="mt-4" variant="outline" onClick={onRetry}>
            Try again
          </Button>
        ) : null}
      </div>
    );
  }
  return <>{empty ?? <p className="px-5 py-16 text-center text-sm text-ink-400">Nothing to show.</p>}</>;
}
