# Polaron V30.3 — directory selection + single-process RAG progress

## Directory selection
- Evidence intake is presented as one local-drive directory workflow.
- The UI no longer requires the examiner to choose individual `.pas`, `.ufd`, `.ufdx`, `.zip`, `.E01`, or other evidence files.
- The examiner opens an available HDD/SSD/USB/external/mapped drive, navigates to the required folder, clicks **Use this directory**, then starts extraction.
- Processing works from the files inside the selected directory.
- The directory picker is the in-app drive browser backed by HostDrive; a native Windows file-open dialog is not used for this flow.

## RAG processing UI
- One progress bar is shown for the process that is currently running.
- The current process name and its percentage are displayed immediately above the bar.
- Completed processes collapse to compact green check marks.
- Pending processes are not rendered as separate progress bars.
- When all stages finish, **RAG ready — 100%** is shown with a green tick.

## Exceptions / Errors
- Errors are no longer mixed into normal progress.
- `job.error` and failed-agent details are displayed in a dedicated **Exceptions / Errors** panel immediately after the RAG Processing panel.
