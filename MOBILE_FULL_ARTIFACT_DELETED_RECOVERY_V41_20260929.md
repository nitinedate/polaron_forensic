# Mobile Full Artifact + Deleted Recovery V41

- Mobile artifact board now surfaces every distinct platform catalog artifact, including zero-count rows, instead of hiding catalog entries with no current evidence.
- User-visible vendor branding is removed from the mobile inventory note, artifact descriptions, and disk-artifact subtitle; mobile board strings are sanitized before rendering.
- Deleted/recovered mobile counts now merge normalized state/family/app recovery results into the board.
- Explicitly deleted WhatsApp rows are counted separately from live WhatsApp messages.
- Added deleted/residual families for Telegram, Signal, Instagram, Facebook/Messenger, Snapchat, Discord, Viber, WeChat, LINE, TikTok, LinkedIn, SMS/MMS, Slack, Teams, and Skype.
- Generic messaging parser now detects multiple message-like tables and marks rows with explicit deleted/revoked/deletion fields as recovered deleted records.
- Added parsers for Instagram, Snapchat, Discord, Viber, WeChat, LINE, TikTok, and LinkedIn databases.
- SQLite freelist/WAL/journal residual recovery remains examiner-labelled as residual/unverified unless an explicit app deletion flag/table proves deletion.
- Logical acquisitions cannot recover deleted content that is no longer present in the acquired files; full-filesystem/physical acquisition is required for filesystem-level unallocated recovery.
