# V42 — Mobile live acquisition, private app data and key-assisted parsing

## Purpose

This release closes the gap between a mobile *artifact catalog* and the evidence actually required to populate that catalog. Importing a logical `.pas/.ufd/.ufdx/.zip` package can only expose data contained in that package. V42 therefore enables live Android acquisition from the Mobile job page while retaining the existing extraction-folder import fallback.

## Android acquisition behavior

When a connected Android phone is selected, the host helper performs the existing shared-storage and provider collection and now also checks whether the device **already** exposes root/su access. V42 does not root a device, exploit a bootloader, bypass a lock screen, or install an elevation mechanism.

If existing root/su is available, V42 reads private evidence without staging temporary files on the handset:

- known messaging/social application private trees under `/data/user/0/<package>` / `/data/data/<package>`;
- WhatsApp and WhatsApp Business `files/key`, `msgstore.db`, WAL/SHM and `wa.db` where readable;
- SMS/MMS telephony databases;
- contacts and calendar databases;
- media-provider databases;
- selected browser private stores;
- SQLite WAL/journal sidecars and other files under the collected app roots.

The reader uses `adb exec-out` plus already-authorised `su`/root and records a limitation when root is unavailable. It does not attempt privilege escalation.

## WhatsApp

V42 separates three states:

1. plaintext `msgstore.db` acquired from private app data — parse directly;
2. encrypted `msgstore-*.crypt12/14/15` plus a collected device key — attempt supported decryption and materialise unique plaintext SQLite databases under `readable_artifacts/whatsapp_decrypted`;
3. encrypted backups without a key — report `key_unavailable`; do not fabricate message/deleted-message counts.

Raw key material is not printed in logs or UI. Only its source path/provenance is recorded by the readable-artifact materialiser.

## Deleted evidence

- Live/plain/decrypted messaging DBs continue through WAL/journal/freelist recovery.
- Historical decrypted WhatsApp backups are retained as unique SQLite databases so older message history can be correlated.
- Fixed a count bug where generic `mobile_deleted_pipeline` parse results could inflate **WhatsApp Deleted Messages** (for example making the deleted count match the number of encrypted backup files). Deleted WhatsApp counts now require WhatsApp-specific recovered/deleted records.

## UI

The Android Mobile job page now enables live USB acquisition. The same panel still provides **Select extraction directory** for existing `.pas/.ufd/.ufdx/.zip` or previously collected folders.

## Important limitations

A device that is locked, unrooted and does not expose private application data cannot yield `/data/user/0` content or WhatsApp private keys through normal ADB/MTP. V42 records this as a capability gap instead of showing a false forensic zero. Modern encryption/TRIM can also make some deleted content unrecoverable even with deeper acquisition.

## Validation

- New V42 focused tests: 4 passed.
- V41 mobile artifact + Android coverage regression set: 15 passed including V42 tests.
- Additional acquisition/inventory/SQLite tests: 20 passed; three older V40 UI-string tests conflict with the intentional V42 live-acquisition behavior / pre-existing UI changes.
- Changed Python modules compile successfully.
- Full frontend build could not complete in the supplied dependency tree because Vite/React packages are missing from the bundled `node_modules`; this is an environment/package-install issue, not a reported TypeScript diagnostic tied to V42 logic.
