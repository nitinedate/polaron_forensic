import { useState } from "react";
import { StopCircle } from "lucide-react";

import { Button } from "../ui";
import { stopAnyUsbAcquisition } from "../../lib/hostDriveHelper";
import { useToast } from "../../lib/toast";

export function StopUsbCollectionButton({
  onStopped,
  className,
}: {
  onStopped?: () => void;
  className?: string;
}) {
  const toast = useToast();
  const [stopping, setStopping] = useState(false);

  async function stop() {
    if (stopping) return;
    setStopping(true);
    try {
      const res = await stopAnyUsbAcquisition();
      if (res?.ok) {
        toast.success(res.message || "USB collection stopped");
        onStopped?.();
      } else {
        toast.error(res?.error || "Could not stop the USB collection");
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not stop the USB collection");
    } finally {
      setStopping(false);
    }
  }

  return (
    <Button
      variant="danger"
      className={className}
      loading={stopping}
      disabled={stopping}
      onClick={() => void stop()}
    >
      <StopCircle className="h-4 w-4" />
      {stopping ? "Stopping…" : "Stop USB collection"}
    </Button>
  );
}

export function UsbCollectionBusyBanner({
  show,
  onStopped,
  className,
}: {
  show: boolean;
  onStopped?: () => void;
  className?: string;
}) {
  if (!show) return null;
  return (
    <div
      className={[
        "flex flex-wrap items-center justify-between gap-3 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2.5 text-sm text-rose-900",
        className || "",
      ].join(" ")}
    >
      <p className="min-w-0 font-medium">
        Another USB collection is already running. Stop it before starting a new job.
      </p>
      <StopUsbCollectionButton onStopped={onStopped} className="shrink-0" />
    </div>
  );
}
