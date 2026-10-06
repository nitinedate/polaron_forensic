# Public HTTPS gateway handoff — release 16

The supplied screenshot shows `acme-bootstrap` publishing `80:80`. That container serves HTTP-01 certificate challenges; it cannot serve HTTPS on 443. The screenshot alone does not establish whether certificate issuance failed or startup was still in progress.

The prod/nitin launchers now start the trusted HTTPS gateway immediately after validating the gateway image, certificate identities/key pairs and nginx configuration. Scanner/Android/iOS compilation and product-stack readiness checks follow. Failures in those later stages leave the already validated gateway and renewal service running, while startup still exits unsuccessfully and identifies incomplete product readiness. The public UI can be available even if an affected API is not ready.

A bootstrap container left by an earlier interrupted launch is removed before starting the gateway, using Compose scoped to `aetheris-gateway`. No unrelated container is removed. Only running Docker containers are considered existing port owners; unrelated IIS/Caddy/Docker listeners are still reported instead of stopped.

The launcher verifies the running gateway exposes host 80 and 443 on a public interface, checks nginx, and verifies certificate trust and IP/domain identity. It does not bypass certificate validation or issue self-signed placeholders. The public Compose override retains `0.0.0.0:80:80`, `0.0.0.0:443:443` and a loopback-only 3001 alias. Existing certificate volumes are retained. Certbot renewal continues every six hours and reloads nginx after renewal. Application recompilation and dependency caching remain enabled.

## Apply on the Windows server

Extract `polaron-public-https-443-fix.zip` into the project root, replacing supplied deployment files. Active `.env`, `script_docker\start_docker.settings.json`, generated nginx configuration, private keys, certificates and evidence are not supplied or overwritten by this patch. Alternatively use the complete updated project.

Open PowerShell as Administrator if the launcher needs to create inbound firewall rules. Check `script_docker\start_docker.settings.json`: `prod.publicIp` must be the static IP assigned to this server; `prod.domain` stays empty. `nitin.publicIp` and `nitin.domain` must identify the same server. Existing profile values are preserved. CLI overrides are saved for later launches.

Use the matching launcher, not both on the same host simultaneously:

```powershell
Set-Location E:\projects\GIT\polaron2
.\script_docker\start_docker_prod.cmd -PublicIP YOUR_STATIC_PUBLIC_IP -AcmeEmail YOUR_EMAIL
```

Or, for the domain profile:

```powershell
Set-Location E:\projects\GIT\polaron2
.\script_docker\start_docker_nitin.cmd -PublicIP YOUR_STATIC_PUBLIC_IP -Domain YOUR_DOMAIN -AcmeEmail YOUR_EMAIL
```

Replace the uppercase placeholders locally. If profiles already contain the correct values, run the corresponding `.cmd` without those arguments. If your project is at `E:\polaron-forensic`, use that path instead.

## Network requirements and acceptance

Forward public TCP 80 and TCP 443 from the router to the current Windows server's LAN IP. Allow those ports through Windows Firewall. The domain A record must point to the configured static IP; remove/fix an incorrect AAAA record if it directs validation elsewhere. HTTP-01 certificate issuance/renewal requires public port 80. A local port binding does not prove external reachability. ISP blocking, router forwarding and DNS cannot be changed or verified by this offline patch.

After launch, inspect the gateway:

```powershell
Set-Location E:\projects\GIT\polaron2
docker compose --project-directory . --project-name aetheris-gateway -f services/gateway/docker-compose.yml -f deployment/windows-ip-https/docker-compose.gateway-local.yml -f deployment/windows-ip-https/docker-compose.gateway-public-https.yml ps gateway certbot-renewer
```

The gateway must show published 80 and 443; the owned bootstrap should be gone. From a different network (for example, phone mobile data), open `https://YOUR_STATIC_PUBLIC_IP/` and, for nitin, `https://YOUR_DOMAIN/`. There must be no certificate name/trust warning. Also check login/API availability; an accessible static UI alone does not prove all products are healthy. Do not use `curl -k` or turn TLS verification off for acceptance.

IP certificates use the Let's Encrypt shortlived profile, so automatic renewal is essential. Official references: https://letsencrypt.org/2026/03/11/shorter-certs-certbot and https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability . Certbot remains pinned at v5.8.0, which supports IP certificates with webroot.

## Validation scope

28 offline HTTPS handoff/binding checks passed, plus 31 existing startup checks, 32 first-launch file checks and 21 certificate/TLS tests (including localhost TLS). Windows scripts parse and retain UTF-8 BOM/CRLF. No Docker daemon, production ACME issuance, router/ISP test or live Windows deployment was available; those acceptance checks remain pending. Earlier application, extraction, SMTP, USB, scanner and UI changes are preserved rather than rerun claims.
