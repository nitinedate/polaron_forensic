import { Component, type ErrorInfo, type ReactNode } from "react";

type Props = { children: ReactNode };
type State = { error: Error | null };

/**
 * Last-resort UI guard. A malformed API row must not turn the entire application
 * into a blank white page. Feature code should still validate data at the API
 * boundary; this component provides a visible recovery path if a render error
 * escapes those checks.
 */
export class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Unhandled UI render error", error, info.componentStack);
  }

  private reload = () => {
    window.location.reload();
  };

  private goBack = () => {
    if (window.history.length > 1) window.history.back();
    else window.location.assign("/");
  };

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <main className="min-h-screen bg-ink-50 px-6 py-16 text-ink-800">
        <div className="mx-auto max-w-2xl rounded-2xl border border-red-100 bg-white p-6 shadow-panel">
          <p className="text-sm font-bold text-red-700">This page could not be rendered.</p>
          <p className="mt-2 text-sm text-ink-600">
            The application caught an unexpected data/rendering error instead of leaving a blank screen.
          </p>
          <pre className="mt-4 max-h-40 overflow-auto rounded-lg bg-ink-950 p-3 text-xs text-white">
            {error.message || "Unknown UI error"}
          </pre>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={this.reload}
              className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white"
            >
              Reload page
            </button>
            <button
              type="button"
              onClick={this.goBack}
              className="rounded-lg border border-ink-200 bg-white px-4 py-2 text-sm font-semibold text-ink-700"
            >
              Go back
            </button>
          </div>
        </div>
      </main>
    );
  }
}
