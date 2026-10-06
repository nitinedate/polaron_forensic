# Job stages above full-width logs — release 15

The shared Disk/Mobile job detail page now uses two stacked sections:
1. Running stages at the top: three cards per row on desktop, two on tablets and one on phones.
2. Full-width processing logs underneath, with a stable 520px panel and vertical scrolling.

Both the acquisition/legacy agent list and the serial processing-stage view use the same responsive card grid. Cards retain stage names, icons, status, percent and item counts. Processing exceptions stay visible.

Log timestamps, stage and agent badges, and severity appear above each message. Message text uses the full panel width and preserves line breaks; long paths/URLs wrap rather than squeezing text into a narrow right-hand column. The old ResizeObserver that matched log height to the stage panel has been removed. Client transfer activity remains client-only, and the progressAgent panel remains below the logs. Scheduling, polling, prerequisite filtering and evidence/report behavior are unchanged.

## Apply

Extract `polaron-job-log-layout-fix.zip` into your project root, replacing the four supplied frontend source files. Rerun your usual deployment launcher so it rebuilds the frontend:

```powershell
Set-Location E:\projects\GIT\polaron2
.\script_docker\start_docker_local.cmd
```

Use `start_docker_nitin.cmd` or `start_docker_prod.cmd` for those installations. If the project resides at `E:\polaron-forensic`, use that path instead. Reload the job page after the launcher finishes.

## Validation

Unified frontend TypeScript/Vite production build passed. The attached screenshot was inspected to identify the narrow message column. Browser rendering verification was attempted, but the browser binary download returned an invalid archive; rendered desktop/tablet/phone screenshots and live Windows UI checks remain pending. No simulated screenshot is presented as the running application. No backend or scanner code changed. Prior test results remain historical.
