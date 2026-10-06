# TLS hostname hotfix for Laptop Scanner v1.5.1

The active central endpoint now uses:

`CENTRAL_API_URL=https://future-softtech.co.in`

Reason: the server certificate presented at the public endpoint has `future-softtech.co.in` in its certificate identity, while connecting by raw IP causes strict TLS hostname verification to fail.

`VERIFY_TLS=true` remains enabled. Do not disable TLS verification to work around a hostname mismatch.

For an already extracted installation, only the `CENTRAL_API_URL` line in `.env` needs to be changed; no scanner image rebuild is required for this endpoint-only correction.
