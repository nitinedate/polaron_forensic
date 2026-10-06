import { useEffect, useState } from "react";
import { jobUploadSession, type JobUploadSnapshot } from "../lib/jobUploadSession";

export function useJobUploadSession(jobId: string): JobUploadSnapshot & { isRunning: boolean } {
  const [snapshot, setSnapshot] = useState(() => jobUploadSession.get(jobId));

  useEffect(() => {
    const session = jobUploadSession.get(jobId);
    if (session.uploading && !jobUploadSession.isRunning(jobId)) {
      jobUploadSession.setUploading(jobId, false);
      jobUploadSession.setProgress(jobId, null);
    }
    setSnapshot(jobUploadSession.get(jobId));
    return jobUploadSession.subscribe(jobId, () => {
      setSnapshot({ ...jobUploadSession.get(jobId) });
    });
  }, [jobId]);

  return {
    ...snapshot,
    isRunning: jobUploadSession.isRunning(jobId),
  };
}
