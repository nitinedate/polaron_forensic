# Access-token SMTP delivery fix — release 12

The reported exception is an SMTP disconnect during AUTH, before message submission. The traceback does not establish which SMTP host, transport, credentials or server policy caused it. `/health` measures API availability; it does not verify email. The old endpoint always returned HTTP 200, including after a mail failure.

Changes:
- STARTTLS on authenticated port 587 and certificate-verified implicit TLS on port 465 (`MAIL_SMTP_SSL` / `SMTP_SSL`; unset means infer from port 465).
- SMTP authentication uses challenge/response instead of an inline initial AUTH response.
- One retry for a disconnect before submission; no automatic retry after message submission begins, avoiding duplicates after an ambiguous disconnect.
- SMTP failure becomes HTTP 503 (`mail_delivery_failed`), with a safe message shown by the existing login UI. Unknown accounts and cooldown requests retain a generic HTTP 200 response; 200 is not proof of delivery.
- Disabled access-token email is reported as a failure. Other intentionally disabled product email remains skipped.
- The token-request UI allows 70 seconds instead of the previous 15-second client timeout.
- Diagnostic tool checks SMTP without sending messages or printing credentials/access tokens.

## Apply on the Windows central server

Extract `polaron-smtp-delivery-fix.zip` into `E:\polaron-forensic`, replacing supplied files. Existing `.env` is not supplied or overwritten. This patch needs the preceding Docker startup/volume fixes. The complete updated project includes them.

Check your existing root `.env`. If using Gmail SMTP, configure the **sending account** (it can differ from the recipient):

```dotenv
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=YOUR_SENDING_ACCOUNT@gmail.com
MAIL_PASSWORD=YOUR_GOOGLE_APP_PASSWORD
MAIL_FROM=YOUR_SENDING_ACCOUNT@gmail.com
MAIL_SMTP_AUTH=true
MAIL_SMTP_STARTTLS=true
MAIL_SMTP_SSL=false
MAIL_SEND_ENABLED=true
```

Replace the placeholders locally. Use a Google app password where available, with 2-Step Verification enabled, rather than the regular account password. Google account/Workspace policy can limit availability. Official reference: https://support.google.com/mail/answer/185833

For SMTP port 465, use `MAIL_PORT=465`, `MAIL_SMTP_SSL=true`, `MAIL_SMTP_STARTTLS=false`. For MailHog capture only, use host `mailhog`, port 1025, auth false, STARTTLS false and SSL false. MailHog stores messages at http://localhost:8025 and does not deliver them to a Gmail inbox.

Rerun your existing deployment profile, for example:

```powershell
Set-Location E:\polaron-forensic
.\script_docker\start_docker_local.cmd
if ($LASTEXITCODE -ne 0) { throw 'Startup failed' }
docker compose --project-name aetheris-forensic -f .\docker-compose.yml exec -T api python -m app.smtp_check --authenticate
if ($LASTEXITCODE -ne 0) { throw 'SMTP check failed; inspect mail configuration and provider/network policy' }
```

For nitin/prod, rerun `start_docker_nitin.cmd` / `start_docker_prod.cmd` respectively; the diagnostic command remains the same. Restarting existing containers alone will not apply `.env` changes; the launcher recreates services with updated settings and rebuilds application code using cached dependencies.

After the diagnostic passes, request a token from the login page for the existing active user. Allow 60 seconds after a failed request before requesting again, because the existing rate limiter holds its cooldown. Check Spam if SMTP accepts the email but it is absent from the inbox. The diagnostic verifies SMTP authentication, not final inbox delivery. Never share `.env`, app passwords or access tokens.

## Validation

21 targeted SMTP tests pass on Python 3.12, including a real localhost SMTP socket exchange with a disconnect on first AUTH followed by successful challenge authentication on the second connection and exactly one accepted synthetic message. Other cases verify TLS selection, certificate context, no credentials sent after a TLS failure, no replay during DATA/submission, accepted mail with QUIT failure, recipient refusal, authentication rejection, disabled email, HTTP 503 and generic unknown-account behavior.

Unified frontend TypeScript/Vite production build also passes. Existing access-token regression tests are included in the test log.

Unified frontend TypeScript/Vite production build also passes. Existing access-token regression tests are included in the test log.

External SMTP/provider credentials and live Windows Docker delivery remain unverified. No external email was sent during these tests. Full package preserves the laptop scanner, existing Docker startup/volume fixes, extraction pipelines and process PDFs byte-for-byte.
