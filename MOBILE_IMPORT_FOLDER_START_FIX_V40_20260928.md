# Mobile image folder import / start-state fix (V40)

## Problems fixed

1. **Mobile image import could open a normal file picker instead of a folder picker.**
   The import flow now uses the browser File System Access directory picker first. The fallback input explicitly sets both `webkitdirectory` and `directory` on the DOM element so Chromium opens a directory chooser rather than asking the examiner to select one `.pas`, `.ufd`, `.ufdx`, or `.zip` file.

2. **Server-attached evidence was mixed with live USB mobile acquisition.**
   `source_type=mobile` is used for existing mobile image/package imports as well as older live-device paths. The import panel now treats live USB acquisition as opt-in (`allowLiveMobileAcquisition`) and defaults it off. Existing image/package import therefore opens the server/client evidence-folder browser and does not show phone rescanning controls.

3. **Folder selection now starts extraction in one step.**
   On the compact mobile import page, choosing **Use this folder** under Server drives immediately confirms the folder, registers it in place, and starts processing because `autoProcess` is enabled. Choosing a client folder does the same after transfer/registration. Server HDD/SSD/USB/network evidence remains zero-copy.

4. **Empty jobs no longer expose premature Process controls.**
   Before evidence is registered, the compact job page shows the folder-selection workflow only. Process / Resume / Stop controls appear after evidence exists or the pipeline has genuinely entered a started status. This prevents a premature `/process` request against an empty `created` job.

5. **Recent mobile jobs no longer show placeholder `created · 0%` rows.**
   The overview uses explicit started pipeline statuses plus actual progress; an empty validation failure is excluded, while a failed job with registered evidence remains visible. The entire Recent mobile jobs card is hidden when there are no actually-started jobs. Empty `created`, `registered`, or pre-start failed records remain hidden.

## Intended examiner flow

- Create Android/iOS import job.
- Click **Select mobile image folder & start**.
- If the image is on a drive attached to the forensic server, select **Server drives → drive → folder → Use this folder**. The evidence is processed in place; no download/upload screen should appear.
- If the evidence is genuinely on a different client computer, choose **Select client folder…** and select the folder. The browser transfers it first, then extraction starts.
- The job appears under **Recent mobile jobs** only after evidence registration/extraction has started.
