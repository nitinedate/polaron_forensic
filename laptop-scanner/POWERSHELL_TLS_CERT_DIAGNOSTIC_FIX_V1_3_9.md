# Aetheris Laptop Scanner v1.3.9 - TLS 1.2 and certificate diagnostic fix

This release addresses Windows PowerShell/.NET errors such as `Could not create SSL/TLS secure channel` after TCP 443 succeeds.

Changes:
- forces TLS 1.2 for the .NET HttpClient scanner control-plane calls;
- performs a no-secret low-level TLS probe that can print the server certificate even when hostname/chain validation fails;
- reports Subject, Issuer, DNS name, SAN, validity dates, negotiated protocol and cipher;
- keeps VERIFY_TLS=true behavior for real authentication and refuses to send tokens over an invalid/untrusted TLS endpoint;
- provides `Test-Windows-TLS-v1.3.9.ps1`.

Recommended sequence:
1. `powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-Windows-TLS-v1.3.9.ps1`
2. If the TLS probe succeeds but verified HTTPS fails, set `CENTRAL_API_URL` to a DNS hostname listed in the certificate SAN that resolves to the server.
3. Re-run the test.
4. Run `Start-Laptop.cmd` only after the verified HTTPS test succeeds.
