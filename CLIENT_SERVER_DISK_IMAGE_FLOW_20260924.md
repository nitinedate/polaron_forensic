# Client vs Server Disk-Image Intake Flow

## Goal

Disk images are handled differently depending on where the evidence physically resides.

### Server-local disk image

When the E01/EWF/raw image is already on a disk attached to the forensic server:

1. Register the existing server path.
2. Do not upload or copy the source image into application staging.
3. Process the image in place from the mounted server path.
4. Persist `disk_source.intake=server_local` and `source_residency=server_local`.
5. Use cleanup policy `never_delete_source`. The platform must never delete examiner/server evidence automatically.

### Client-side disk image

When the image is on the analyst/client computer and is not available on the forensic server:

1. Start the Download Agent before the first byte is transferred.
2. Upload at most **5 image files concurrently** using the bounded browser worker/semaphore pool.
3. Stage each image once under `DATA_ROOT/uploads/<job>/intake` on the forensic server.
4. Disk images are not duplicated into object storage during intake. Extraction reads the server staging path directly.
5. Do not start List Folder, segment registration, virtual-disk build, or extraction until every selected image file has arrived successfully.
6. Register the completed server staging folder and start the normal extraction pipeline.
7. Keep the uploaded source if the job fails, pauses, or is interrupted so that resume/retry remains possible.
8. Delete the uploaded staging source only after verified successful completion (`status=ready`, pipeline phase `complete`, 100% progress, and extraction complete).
9. Cleanup removes the staging directory and any legacy `client-uploads/<job>/` object copies. Extracted artifacts and permanent job storage remain intact.

## Performance rationale

A fixed upper bound of five simultaneous large HTTP transfers gives significantly better throughput for segmented E01 sets without allowing an arbitrary number of 8 MB streaming writers to compete for disk, RAM, network buffers, and extraction workers. Extraction remains separately controlled by the adaptive CPU/GPU/thermal governor.

## Forensic safety

- Original server-local evidence is never deleted by this workflow.
- Client-uploaded source is retained on any unsuccessful or incomplete job.
- SHA-256 is calculated while each client file is staged.
- Database evidence records and hashes are retained after successful staging cleanup for provenance.
- Cleanup occurs only after the complete pipeline has reached a verified success state so later parsers/materializers cannot lose access to the source image mid-case.

## V27 hardening — full-intake barrier

V27 strengthens the client workflow so **no downstream pipeline stage can run until the entire declared image set is present and registered**. The browser opens the intake gate before transfer, uploads no more than five files at once, publishes completed files atomically, and the server keeps the job in `receiving`/`verifying` until both physical staged-file count and database received count satisfy the declared manifest. Extraction, parse, Phase 3, inventory, OCR, RAG, graph and report tasks also have a defensive task-level gate.

The server-side workflow is now available from LAN/domain browser sessions through the server drive browser. Server-attached SSD/HDD/USB and server-accessible network drives are registered and read in place; they are not uploaded, duplicated, or deleted by client cleanup.
