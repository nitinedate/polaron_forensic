import { useCallback, useEffect, useRef, useState, type CSSProperties, type PointerEvent as ReactPointerEvent } from "react";

type Offset = { x: number; y: number };

export function useDraggablePanel(open: boolean) {
  const [offset, setOffset] = useState<Offset>({ x: 0, y: 0 });
  const dragging = useRef(false);
  const start = useRef({ x: 0, y: 0, ox: 0, oy: 0 });

  useEffect(() => {
    if (open) setOffset({ x: 0, y: 0 });
  }, [open]);

  const onPointerDown = useCallback(
    (e: ReactPointerEvent<HTMLElement>) => {
      const target = e.target as HTMLElement;
      if (target.closest("button, a, input, textarea, select, [data-no-drag]")) return;
      dragging.current = true;
      start.current = { x: e.clientX, y: e.clientY, ox: offset.x, oy: offset.y };
      e.currentTarget.setPointerCapture(e.pointerId);
    },
    [offset]
  );

  const onPointerMove = useCallback((e: ReactPointerEvent<HTMLElement>) => {
    if (!dragging.current) return;
    setOffset({
      x: start.current.ox + e.clientX - start.current.x,
      y: start.current.oy + e.clientY - start.current.y,
    });
  }, []);

  const endDrag = useCallback((e: ReactPointerEvent<HTMLElement>) => {
    dragging.current = false;
    try {
      e.currentTarget.releasePointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
  }, []);

  const panelStyle: CSSProperties = {
    transform: `translate(calc(-50% + ${offset.x}px), calc(-50% + ${offset.y}px))`,
  };

  const dragHandleProps = {
    onPointerDown,
    onPointerMove,
    onPointerUp: endDrag,
    onPointerCancel: endDrag,
    className: "cursor-grab active:cursor-grabbing select-none touch-none",
  };

  return { panelStyle, dragHandleProps };
}
