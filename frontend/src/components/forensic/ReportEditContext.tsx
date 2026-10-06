import {
  createContext,
  useContext,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import { HUMAN_EDIT_COLOR, closestLine, diffTokens } from "../../lib/reportTextDiff";

export type ReportEditState = {
  editing: boolean;
  baselineLines: string[];
  sectionKey: string;
};

const ReportEditContext = createContext<ReportEditState>({
  editing: false,
  baselineLines: [],
  sectionKey: "",
});

export function ReportEditProvider({
  editing,
  baselineLines,
  sectionKey,
  children,
}: {
  editing: boolean;
  baselineLines: string[];
  sectionKey: string;
  children: ReactNode;
}) {
  return (
    <ReportEditContext.Provider value={{ editing, baselineLines, sectionKey }}>
      {children}
    </ReportEditContext.Provider>
  );
}

export function useReportEdit(): ReportEditState {
  return useContext(ReportEditContext);
}

/** Paint words that differ from the generated baseline in blue. */
export function HumanEditText({ text }: { text: string }) {
  const { editing, baselineLines } = useReportEdit();
  if (editing || !text) return <>{text}</>;
  if (!baselineLines.length) return <>{text}</>;
  const orig = closestLine(text, baselineLines);
  if (!orig) {
    return <span className="report-human-edit">{text}</span>;
  }
  if (orig === text) return <>{text}</>;
  const tokens = diffTokens(orig, text);
  return (
    <>
      {tokens.map((tok, i) =>
        tok.op === "del" ? null : tok.op === "ins" ? (
          <span key={i} className="report-human-edit">
            {tok.value}
          </span>
        ) : (
          <span key={i}>{tok.value}</span>
        ),
      )}
    </>
  );
}

function paintTypingBlue() {
  try {
    document.execCommand("styleWithCSS", false, "true");
    document.execCommand("foreColor", false, HUMAN_EDIT_COLOR);
  } catch {
    /* execCommand is the in-page typing color; ignore if unavailable */
  }
}

/** While editing, the live page is contentEditable; new/changed words type in blue. */
export function EditableReportBody({ children }: { children: ReactNode }) {
  const { editing, sectionKey } = useReportEdit();
  const viewRef = useRef<HTMLDivElement>(null);
  const editRef = useRef<HTMLDivElement>(null);
  const seeded = useRef(false);

  useEffect(() => {
    if (!editing) {
      seeded.current = false;
      return;
    }
    const edit = editRef.current;
    const view = viewRef.current;
    if (!edit || !view || seeded.current) return;
    edit.innerHTML = view.innerHTML;
    seeded.current = true;
    paintTypingBlue();
  }, [editing]);

  return (
    <>
      <div ref={viewRef} className={editing ? "hidden" : undefined}>
        {children}
      </div>
      {editing ? (
        <div
          ref={editRef}
          className="report-inline-editor min-h-[4rem] cursor-text outline-none"
          data-section-key={sectionKey}
          contentEditable
          suppressContentEditableWarning
          spellCheck
          onBeforeInput={(e) => {
            const inputType = (e.nativeEvent as unknown as { inputType?: string }).inputType ?? "";
            if (inputType.startsWith("insert")) paintTypingBlue();
          }}
          onKeyDown={(e) => {
            if (e.ctrlKey || e.metaKey || e.altKey) return;
            if (e.key.length === 1 || e.key === "Enter") paintTypingBlue();
          }}
          onPaste={(e) => {
            e.preventDefault();
            const text = e.clipboardData.getData("text/plain");
            paintTypingBlue();
            document.execCommand("insertText", false, text);
          }}
        />
      ) : null}
    </>
  );
}

export function editorsForSection(sectionKey: string): HTMLElement[] {
  return [...document.querySelectorAll(`.report-inline-editor[data-section-key="${CSS.escape(sectionKey)}"]`)] as HTMLElement[];
}
