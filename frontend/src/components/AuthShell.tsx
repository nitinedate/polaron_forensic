import type { ReactNode } from "react";

/**
 * Centered card on a soft gradient backdrop (login / forgot / reset screens).
 */
export function AuthShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="container-fluid relative flex min-h-screen items-center justify-center overflow-hidden bg-gradient-to-br from-brand-50 via-white to-accent-50 px-4 py-10">
      <div className="pointer-events-none absolute -left-24 -top-24 h-72 w-72 rounded-full bg-brand-300/25 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-24 -right-24 h-72 w-72 rounded-full bg-accent-200/35 blur-3xl" />

      <div className="relative w-full max-w-md">
        <div className="card px-7 py-8 shadow-soft">
          <div className="mb-6">
            <div className="mb-4 flex w-full items-center justify-center bg-transparent px-1 py-1">
              <img src="/logo.png" alt="Polaron Technologies" className="h-[4.75rem] w-auto max-w-full object-contain" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-ink-900">{title}</h1>
            {subtitle && <p className="mt-1.5 text-sm text-ink-500">{subtitle}</p>}
          </div>
          {children}
        </div>
        {footer && <div className="mt-5 text-center text-sm text-ink-500">{footer}</div>}
      </div>
    </div>
  );
}
