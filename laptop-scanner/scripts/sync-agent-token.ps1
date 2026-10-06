# Links this laptop to Service 3 with the same emailed access token as the web UIs.
# 1) Always prompt for the access token from the Aetheris login email.
# 2) Token-login; refuse to link if that fails.
# 3) Bind AGENT_TOKEN to that same emailed token.

function Get-Utf8NoBom {
    New-Object System.Text.UTF8Encoding $false
}

function Get-ApiRoot([string]$Base) {
    $rootUrl = ($Base | ForEach-Object { $_.Trim().TrimEnd('/') })
    if ($rootUrl -match 'host\.docker\.internal') {
        $rootUrl = $rootUrl -replace 'host\.docker\.internal', '127.0.0.1'
    }
    if ($rootUrl.ToLower().EndsWith('/api')) {
        $rootUrl = $rootUrl.Substring(0, $rootUrl.Length - 4).TrimEnd('/')
    }
    return $rootUrl
}

function Get-VerifyTls([hashtable]$EnvMap) {
    $raw = ([string]$EnvMap['VERIFY_TLS']).Trim().ToLower()
    return -not ($raw -in @('0', 'false', 'no', 'off'))
}

function Get-ExceptionChainText([System.Exception]$Exception) {
    $parts = New-Object System.Collections.Generic.List[string]
    $e = $Exception
    while ($null -ne $e) {
        if (-not [string]::IsNullOrWhiteSpace([string]$e.Message)) {
            $parts.Add(([string]$e.Message).Trim())
        }
        $e = $e.InnerException
    }
    return (($parts | Select-Object -Unique) -join ' -> ')
}


function Get-AetherisTlsPeerInfo {
    param(
        [string]$Base,
        [int]$TimeoutSec = 10
    )

    $tcp = $null
    $ssl = $null
    try {
        $u = [Uri](Get-ApiRoot $Base)
        if ($u.Scheme -ne 'https') {
            return [pscustomobject]@{ Ok=$false; Error='Certificate probe requires an https:// URL.' }
        }
        $port = if ($u.IsDefaultPort) { 443 } else { $u.Port }
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($u.Host, $port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne([Math]::Max(1000, $TimeoutSec * 1000))) {
            throw "TCP connect timeout to $($u.Host):$port"
        }
        $tcp.EndConnect($iar)

        # This probe intentionally ignores certificate validation only so it can
        # print the certificate presented by the server. It sends no token,
        # credentials, request body, or HTTP request.
        $validation = { param($sender, $certificate, $chain, $sslPolicyErrors) return $true }
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $validation)
        $clientCerts = New-Object System.Security.Cryptography.X509Certificates.X509CertificateCollection
        $ssl.AuthenticateAsClient(
            $u.Host,
            $clientCerts,
            [System.Security.Authentication.SslProtocols]::Tls12,
            $false
        )
        if ($null -eq $ssl.RemoteCertificate) {
            throw 'TLS handshake completed but no server certificate was presented.'
        }
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $sanParts = @()
        foreach ($ext in $cert.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.17') {
                try { $sanParts += $ext.Format($false) } catch { }
            }
        }
        $dnsName = ''
        try { $dnsName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false) } catch { }
        return [pscustomobject]@{
            Ok = $true
            Host = $u.Host
            Port = $port
            Protocol = [string]$ssl.SslProtocol
            Cipher = [string]$ssl.CipherAlgorithm
            CipherStrength = [int]$ssl.CipherStrength
            Subject = [string]$cert.Subject
            Issuer = [string]$cert.Issuer
            DnsName = [string]$dnsName
            SubjectAltName = (($sanParts | Where-Object { $_ }) -join '; ')
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            Thumbprint = [string]$cert.Thumbprint
            Error = ''
        }
    } catch {
        return [pscustomobject]@{
            Ok = $false
            Error = (Get-ExceptionChainText $_.Exception)
        }
    } finally {
        if ($null -ne $ssl) { try { $ssl.Dispose() } catch { } }
        if ($null -ne $tcp) { try { $tcp.Close() } catch { } }
    }
}

function Invoke-AetherisHttp {
    param(
        [string]$Method,
        [string]$Url,
        [string]$Tenant,
        [string]$AccessToken,
        $BodyObject,
        [bool]$VerifyTls = $true,
        [bool]$FollowRedirects = $false,
        [int]$TimeoutSec = 45
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop

    $oldProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $oldCertCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    $client = $null
    $handler = $null
    $request = $null
    $response = $null
    try {
        # Prefer .NET HttpClient over Windows curl.exe. The inbox Windows curl
        # uses Schannel and can fail with SEC_E_INTERNAL_ERROR / 0x80090304
        # ('The Local Security Authority cannot be contacted') even when .NET
        # HttpClient can establish the same TLS connection.
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = $oldProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        } catch { }

        if (-not $VerifyTls) {
            # VERIFY_TLS=false is intended only for controlled/self-signed test
            # deployments. Keep normal hostname/chain validation on by default.
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }

        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $FollowRedirects
        $handler.MaxAutomaticRedirections = 5
        $handler.UseCookies = $false
        $handler.UseDefaultCredentials = $false
        try {
            # Avoid Windows automatically searching the certificate store for a
            # client certificate. That path can involve LSASS/Schannel and is
            # not required by Aetheris token authentication.
            $handler.ClientCertificateOptions = [System.Net.Http.ClientCertificateOption]::Manual
        } catch { }
        try {
            # Windows PowerShell 5.1 / .NET Framework can otherwise negotiate
            # legacy protocol defaults on older machines. Aetheris requires
            # modern HTTPS; force TLS 1.2 for the scanner control plane.
            if ($handler.PSObject.Properties.Name -contains 'SslProtocols') {
                $handler.SslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
            }
        } catch { }
        try {
            if (-not $VerifyTls -and $handler.PSObject.Properties.Name -contains 'ServerCertificateCustomValidationCallback') {
                $handler.ServerCertificateCustomValidationCallback = { param($message, $cert, $chain, $errors) return $true }
            }
        } catch { }

        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds([Math]::Max(5, $TimeoutSec))

        $httpMethod = [System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant())
        $request = [System.Net.Http.HttpRequestMessage]::new($httpMethod, $Url)
        [void]$request.Headers.TryAddWithoutValidation('X-Tenant', $Tenant)
        [void]$request.Headers.TryAddWithoutValidation('User-Agent', 'Aetheris-Laptop-Scanner/1.4.5')
        if (-not [string]::IsNullOrWhiteSpace($AccessToken)) {
            [void]$request.Headers.TryAddWithoutValidation('Authorization', "Bearer $AccessToken")
        }
        if ($null -ne $BodyObject) {
            $json = $BodyObject | ConvertTo-Json -Compress -Depth 8
            $request.Content = [System.Net.Http.StringContent]::new($json, [Text.Encoding]::UTF8, 'application/json')
        }

        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $body = ''
        if ($null -ne $response.Content) {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
        $effective = $Url
        if ($null -ne $response.RequestMessage -and $null -ne $response.RequestMessage.RequestUri) {
            $effective = $response.RequestMessage.RequestUri.AbsoluteUri
        }
        $location = ''
        if ($null -ne $response.Headers.Location) {
            $location = [string]$response.Headers.Location
        }
        return [pscustomobject]@{
            Status = [int]$response.StatusCode
            Body = $body
            EffectiveUrl = $effective
            Location = $location
            Error = ''
            Transport = 'dotnet-httpclient'
        }
    } catch {
        $detail = Get-ExceptionChainText $_.Exception
        return [pscustomobject]@{
            Status = -1
            Body = ''
            EffectiveUrl = $Url
            Location = ''
            Error = $detail
            Transport = 'dotnet-httpclient'
        }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        if ($null -ne $handler) { $handler.Dispose() }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCertCallback
        [System.Net.ServicePointManager]::SecurityProtocol = $oldProtocol
    }
}

function Resolve-CentralApiBase {
    param(
        [string]$Base,
        [string]$Tenant,
        [bool]$VerifyTls = $true
    )

    $rootUrl = Get-ApiRoot $Base
    if ([string]::IsNullOrWhiteSpace($rootUrl)) {
        throw 'CENTRAL_API_URL is empty.'
    }

    # Resolve redirects before any secret/token is sent. This is deliberately a
    # GET to /api/health with no Authorization header and no request body.
    $healthUrl = $rootUrl + '/api/health'
    $probe = Invoke-AetherisHttp -Method 'GET' -Url $healthUrl -Tenant $Tenant -AccessToken '' -BodyObject $null -VerifyTls $VerifyTls -FollowRedirects $true -TimeoutSec 45
    if ($probe.Status -lt 0) {
        $detail = ([string]$probe.Error).Trim()
        $peer = $null
        if ($rootUrl -match '(?i)^https://') {
            $peer = Get-AetherisTlsPeerInfo -Base $rootUrl -TimeoutSec 10
        }

        if ($null -ne $peer -and $peer.Ok) {
            $certText = "TLS transport succeeded with $($peer.Protocol), but the verified HTTPS request failed.`nServer certificate Subject: $($peer.Subject)`nServer certificate DNS name: $($peer.DnsName)`nServer certificate SAN: $($peer.SubjectAltName)`nCertificate valid: $($peer.NotBefore) to $($peer.NotAfter)"
            if ($VerifyTls) {
                throw "TLS certificate validation/hostname failed for CENTRAL_API_URL=${Base}. $detail`n$certText`nUse a CENTRAL_API_URL hostname that is present in the certificate SAN/DNS name and resolves to this server, or install the issuing CA if this is a private CA. Keep VERIFY_TLS=true in production."
            }
            throw "HTTPS request failed for CENTRAL_API_URL=${Base}: $detail`n$certText"
        }

        if ($detail -match '(?i)Local Security Authority|SEC_E_INTERNAL_ERROR|0x80090304') {
            throw "Windows TLS failed while connecting to CENTRAL_API_URL=${Base}: $detail`nThe v1.3.9 .NET transport forces TLS 1.2 and avoids Windows curl.exe. The low-level TLS probe also failed: $([string]$peer.Error)"
        }
        if ($detail -match '(?i)certificate|authentication failed|SSL|TLS|secure channel|remote certificate') {
            $peerError = if ($null -ne $peer) { [string]$peer.Error } else { '' }
            throw "TLS handshake failed for CENTRAL_API_URL=${Base}: $detail`nLow-level TLS 1.2 probe: $peerError`nConfirm the server supports TLS 1.2 and use the DNS name from its certificate."
        }
        throw "Cannot reach CENTRAL_API_URL=${Base}: $detail"
    }

    $effectiveUrl = ([string]$probe.EffectiveUrl).Trim()
    if ([string]::IsNullOrWhiteSpace($effectiveUrl)) {
        throw "Could not determine the final URL for CENTRAL_API_URL=$Base."
    }
    try { $u = [Uri]$effectiveUrl } catch { throw "Central redirect returned an invalid URL: $effectiveUrl" }
    if ($u.Scheme -notin @('http', 'https')) {
        throw "Central redirect used unsupported scheme '$($u.Scheme)'. Only HTTP/HTTPS are allowed."
    }

    $path = $u.AbsolutePath.TrimEnd('/')
    $suffix = '/api/health'
    if ($path.ToLower().EndsWith($suffix)) {
        $prefix = $path.Substring(0, $path.Length - $suffix.Length).TrimEnd('/')
        $resolved = ($u.GetLeftPart([System.UriPartial]::Authority) + $prefix).TrimEnd('/')
    } else {
        $resolved = $u.GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')
    }

    if ($Base -match '(?i)host\.docker\.internal' -and $u.Host -in @('127.0.0.1', 'localhost')) {
        $resolved = $resolved -replace '(?i)://127\.0\.0\.1(?=[:/]|$)', '://host.docker.internal'
        $resolved = $resolved -replace '(?i)://localhost(?=[:/]|$)', '://host.docker.internal'
    }

    return [pscustomobject]@{
        Base = $resolved
        HealthStatus = [int]$probe.Status
        EffectiveHealthUrl = $effectiveUrl
        Transport = [string]$probe.Transport
    }
}

function Read-TokenFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { return '' }
    $text = ''
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
        $text = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
    } elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        $text = [Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    } else {
        $nulCount = 0
        foreach ($b in $bytes) { if ($b -eq 0) { $nulCount++ } }
        if ($nulCount -gt ($bytes.Length / 4)) {
            $text = [Text.Encoding]::Unicode.GetString($bytes)
        } else {
            $text = [Text.Encoding]::UTF8.GetString($bytes)
        }
    }
    return ($text.Trim())
}

function Set-DotEnvValue([string]$Path, [string]$Key, [string]$Value) {
    $lines = @()
    if (Test-Path -LiteralPath $Path) {
        $lines = [IO.File]::ReadAllLines($Path)
    }
    $found = $false
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match ('^\s*' + [regex]::Escape($Key) + '\s*=')) {
            if (-not $found) {
                $out.Add("$Key=$Value")
                $found = $true
            }
        } else {
            $out.Add($line)
        }
    }
    if (-not $found) { $out.Add("$Key=$Value") }
    [IO.File]::WriteAllLines($Path, $out.ToArray(), (Get-Utf8NoBom))
}

function Get-AgentTokenComposeFile {
    param([string]$Root)
    foreach ($name in @('docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml')) {
        $candidate = Join-Path $Root $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return $null
}

function Stop-AndRemove-ScannerAgentForTokenRepair {
    param([string]$Root)
    $compose = Get-AgentTokenComposeFile -Root $Root
    if (-not $compose) { return }
    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = @(& docker.exe compose -f $compose rm -f -s scanner-agent 2>&1)
        $rc = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }
    if ($rc -eq 0) {
        Write-Host '[OK] Removed scanner-agent container so the token runtime path can be repaired safely.' -ForegroundColor Green
    } else {
        $text = (@($out | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
        if ($text -and $text -notmatch 'No stopped containers') {
            Write-Host ("[WARN] scanner-agent cleanup returned exit {0}: {1}" -f $rc,$text) -ForegroundColor Yellow
        }
    }
}

function Ensure-AgentTokenHostFile {
    param(
        [string]$Root,
        [string]$TokenFile
    )
    $tokenDir = Split-Path -Parent $TokenFile
    if (-not (Test-Path -LiteralPath $tokenDir -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $tokenDir | Out-Null
    }

    # Docker bind mounts create a DIRECTORY when a missing host file is used with
    # short volume syntax. That makes File.WriteAllText fail with AccessDenied.
    if (Test-Path -LiteralPath $TokenFile -PathType Container) {
        Write-Host '[WARN] scanner-agent\runtime\agent-token is unexpectedly a directory. Repairing it as a file.' -ForegroundColor Yellow
        Stop-AndRemove-ScannerAgentForTokenRepair -Root $Root
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backup = "$TokenFile.directory-backup-$stamp"
        try {
            Move-Item -LiteralPath $TokenFile -Destination $backup -Force
            Write-Host ("[OK] Preserved legacy token directory as {0}" -f $backup) -ForegroundColor Green
        } catch {
            throw "Could not move legacy token directory '$TokenFile'. Close processes using it and retry. $($_.Exception.Message)"
        }
    }

    if (-not (Test-Path -LiteralPath $TokenFile -PathType Leaf)) {
        [IO.File]::WriteAllBytes($TokenFile, [byte[]]@())
    }

    try {
        $item = Get-Item -LiteralPath $TokenFile -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
            $item.Attributes = ($item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
        }
    } catch {
        # The actual writable probe below gives the actionable error.
    }

    $stream = $null
    try {
        $stream = New-Object IO.FileStream($TokenFile,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    } catch {
        throw "AGENT token file is not writable: $TokenFile. Check Windows ACL/Controlled Folder Access and retry. $($_.Exception.Message)"
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Save-AgentToken {
    param(
        [string]$Root,
        [string]$EnvPath,
        [string]$Token
    )
    $token = ($Token | ForEach-Object { $_.Trim() })
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Refusing to save an empty AGENT_TOKEN.' }
    $tokenFile = Join-Path $Root 'scanner-agent\runtime\agent-token'
    Ensure-AgentTokenHostFile -Root $Root -TokenFile $tokenFile
    [IO.File]::WriteAllText($tokenFile, $token + [Environment]::NewLine, (Get-Utf8NoBom))
    Set-DotEnvValue -Path $EnvPath -Key 'AGENT_TOKEN' -Value $token
    # The running Docker stack bind-mounts E:\laptop-scanner. If Start-Laptop
    # was launched from D: or another copy, still update the live token file.
    foreach ($liveRoot in @('E:\laptop-scanner', 'D:\laptop-scanner')) {
        if ($liveRoot -eq $Root) { continue }
        $liveEnv = Join-Path $liveRoot '.env'
        $liveToken = Join-Path $liveRoot 'scanner-agent\runtime\agent-token'
        if (-not (Test-Path -LiteralPath $liveEnv)) { continue }
        Set-DotEnvValue -Path $liveEnv -Key 'AGENT_TOKEN' -Value $token
        Ensure-AgentTokenHostFile -Root $liveRoot -TokenFile $liveToken
        [IO.File]::WriteAllText($liveToken, $token + [Environment]::NewLine, (Get-Utf8NoBom))
        Write-Host "[OK] Also wrote AGENT_TOKEN to $liveRoot so the running stack can claim jobs."
    }
}

function Invoke-JsonApi {
    param(
        [string]$Method,
        [string]$Url,
        [string]$Tenant,
        [string]$AccessToken,
        $BodyObject,
        [bool]$VerifyTls = $true
    )
    # Secret-bearing API requests intentionally do NOT auto-follow redirects.
    # Resolve-CentralApiBase runs first without secrets and persists the final
    # canonical URL. This prevents a token/body from being forwarded to an
    # unexpected redirect target.
    return Invoke-AetherisHttp -Method $Method -Url $Url -Tenant $Tenant -AccessToken $AccessToken -BodyObject $BodyObject -VerifyTls $VerifyTls -FollowRedirects $false -TimeoutSec 45
}

function Test-AgentToken {
    param(
        [string]$Base,
        [string]$Tenant,
        [string]$Token,
        [bool]$VerifyTls = $true
    )
    if ([string]::IsNullOrWhiteSpace($Token) -or $Token -eq 'replace-me') { return 0 }
    $rootUrl = Get-ApiRoot $Base
    $hb = Invoke-JsonApi -Method 'POST' -Url ($rootUrl + '/api/scanner-agent/heartbeat') -Tenant $Tenant -AccessToken $Token -BodyObject @{} -VerifyTls $VerifyTls
    if ($hb.Status -ge 200 -and $hb.Status -lt 300) { return $hb.Status }
    if ($hb.Status -eq 401 -or $hb.Status -eq 403) { return $hb.Status }
    $jobs = Invoke-JsonApi -Method 'GET' -Url ($rootUrl + '/api/scanner-agent/jobs/next') -Tenant $Tenant -AccessToken $Token -BodyObject $null -VerifyTls $VerifyTls
    if ($jobs.Status -eq 401 -or $jobs.Status -eq 403) { return $jobs.Status }
    if ($hb.Status -ne -1 -and $hb.Status -ne 0) { return $hb.Status }
    return $jobs.Status
}

function Add-TokenCandidate {
    param(
        $List,
        [string]$Source,
        [string]$Value
    )
    $v = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($v) -or $v -eq 'replace-me') { return }
    foreach ($existing in $List) {
        if ($existing.Value -eq $v) { return }
    }
    $List.Add([pscustomobject]@{ Source = $Source; Value = $v })
}

function Get-LocalTokenCandidates {
    param(
        [string]$Root,
        [hashtable]$EnvMap
    )
    $list = New-Object System.Collections.Generic.List[object]
    Add-TokenCandidate $list 'AGENT_TOKEN (.env)' ([string]$EnvMap['AGENT_TOKEN'])
    Add-TokenCandidate $list 'scanner-agent/runtime/agent-token' (Read-TokenFile (Join-Path $Root 'scanner-agent\runtime\agent-token'))
    # v1.4.5 and older compatibility: read a legacy token file once, but never bind it into the container.
    Add-TokenCandidate $list 'legacy scanner-agent/.agent-token' (Read-TokenFile (Join-Path $Root 'scanner-agent\.agent-token'))
    Add-TokenCandidate $list 'AGENT_RECOVERY_TOKEN (.env)' ([string]$EnvMap['AGENT_RECOVERY_TOKEN'])
    Add-TokenCandidate $list 'scanner-agent/.agent-recovery-token' (Read-TokenFile (Join-Path $Root 'scanner-agent\.agent-recovery-token'))
    return $list
}

function ConvertFrom-JsonSafe([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        return ($Text | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Resolve-LoginEmail {
    param(
        [string]$UserName,
        [string]$Domain = ''
    )
    $user = ([string]$UserName).Trim()
    $dom = ([string]$Domain).Trim()
    if ($user -match '\\') {
        $parts = $user -split '\\', 2
        if ($parts.Count -eq 2) {
            $dom = $parts[0]
            $user = $parts[1]
        }
    }
    # Windows credential dialog splits name@company.com into User=name, Domain=company.com.
    if ($user -notmatch '@' -and $dom -match '\.') {
        $user = "$user@$dom"
    }
    return $user.Trim().ToLower()
}

function Read-ConsoleSecret([string]$Prompt) {
    $secure = Read-Host $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-ApiErrorText($Response) {
    if ($null -eq $Response) { return '' }
    $json = ConvertFrom-JsonSafe ([string]$Response.Body)
    $candidates = @(
        [string]$json.detail.error.message,
        [string]$json.detail.message,
        [string]$json.error.message,
        [string]$json.message
    )
    foreach ($msg in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($msg)) { return $msg.Trim() }
    }
    $snip = ([string]$Response.Body).Trim()
    if ($snip.Length -gt 180) { $snip = $snip.Substring(0, 180) }
    return $snip
}

function Get-ClientAccessTokenPrompt {
    param(
        [string]$Tenant
    )
    if (-not [Environment]::UserInteractive) {
        throw 'Start-Laptop must run interactively so it can ask for the access token from the Aetheris login email.'
    }
    Write-Host ''
    Write-Host 'The emailed access token is required before this laptop can link to the server.'
    Write-Host "On any Aetheris login page, request a token for organization $Tenant, then paste it here."
    Write-Host 'The same token signs into Forensic, Mobile extract, and this laptop scanner.'
    Write-Host 'Stored AGENT_TOKEN in .env is not enough to skip this prompt.'
    Write-Host ''
    $token = ((Read-Host 'Access token from login email') -replace '\s', '')
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw 'Access token was empty. Re-run Start-Laptop and paste the token from the login email.'
    }
    $parts = $token.Split('.')
    $digest = if ($parts.Length -gt 0) { [string]$parts[$parts.Length - 1] } else { '' }
    if ($parts.Length -lt 4 -or $parts[0] -ne 'ath1' -or $token.IndexOf('@') -lt 0 -or $digest -notmatch '^[0-9a-fA-F]{64}$') {
        throw @"
The pasted value is not a complete emailed access token.
Paste the whole token on one line. It starts with ath1.$Tenant. and ends with a 64-character code.
If the email wrapped the token, copy the Access token line only, with no spaces or line breaks.
"@
    }
    return $token
}

function Get-AccessTokenTenant([string]$Token) {
    $parts = ([string]$Token).Split('.')
    if ($parts.Length -lt 2) { return '' }
    return ([string]$parts[1]).Trim().ToLower()
}

function Get-ClientSessionToken {
    param(
        [string]$Base,
        [string]$Tenant,
        [string]$ClientToken,
        [bool]$VerifyTls = $true
    )
    $rootUrl = Get-ApiRoot $Base
    Write-Host ("[INFO] Signing in with the emailed access token (organization {0})." -f $Tenant)
    $login = Invoke-JsonApi -Method 'POST' -Url ($rootUrl + '/api/auth/token-login') -Tenant $Tenant -AccessToken $null -BodyObject @{ token = $ClientToken } -VerifyTls $VerifyTls
    if ($login.Status -lt 200 -or $login.Status -ge 300) {
        if ($login.Status -lt 0 -and -not [string]::IsNullOrWhiteSpace([string]$login.Error)) {
            throw "Token login network/TLS failure: $($login.Error)"
        }
        $detail = Get-ApiErrorText $login
        if ($detail) {
            throw "Token login failed (HTTP $($login.Status)): $detail. Check TENANT_SLUG=$Tenant and the token from the login email for $Base"
        }
        throw "Token login failed (HTTP $($login.Status)). Check TENANT_SLUG and the emailed access token for $Base"
    }
    $json = ConvertFrom-JsonSafe $login.Body
    if ($null -eq $json) { throw 'Token login returned an unreadable response.' }
    $access = [string]$json.access_token
    if ([string]::IsNullOrWhiteSpace($access)) {
        throw 'Token login did not return a session token.'
    }
    return $access
}

function Select-EdgeScanner {
    param(
        $Items,
        [hashtable]$EnvMap,
        [string]$Computer
    )
    $edge = @($Items | Where-Object {
        $mode = ([string]$_.connection_mode).ToLower()
        $url = ([string]$_.url).ToLower()
        $role = ([string]$_.scanner_role).ToLower()
        $mode -eq 'edge_agent' -or $url.StartsWith('agent://') -or $role -in @('portable', 'persistent_edge')
    })
    if ($edge.Count -eq 0) { return $null }
    $id = ([string]$EnvMap['SCANNER_ID']).Trim()
    if ($id) {
        $hit = @($edge | Where-Object { [string]$_.id -eq $id } | Select-Object -First 1)
        if ($hit) { return $hit }
    }
    $wantName = ([string]$EnvMap['SCANNER_NAME']).Trim()
    if (-not $wantName) { $wantName = "Laptop-$Computer" }
    $hit = @($edge | Where-Object { [string]$_.name -eq $wantName } | Select-Object -First 1)
    if ($hit) { return $hit }
    $role = ([string]$EnvMap['SCANNER_ROLE']).Trim()
    if (-not $role) { $role = 'portable' }
    $byRole = @($edge | Where-Object { ([string]$_.scanner_role).ToLower() -eq $role.ToLower() })
    $byName = @($edge | Where-Object { ([string]$_.name).ToLower() -eq 'laptop' -or ([string]$_.name -like 'Laptop-*') })
    if ($byName.Count -eq 1) { return $byName[0] }
    if ($byRole.Count -eq 1) { return $byRole[0] }
    if ($edge.Count -eq 1) { return $edge[0] }
    return $null
}

function Bind-EdgeScannerToken {
    param(
        [string]$Base,
        [string]$Tenant,
        [string]$AccessToken,
        [string]$ClientToken,
        [hashtable]$EnvMap,
        [bool]$VerifyTls = $true,
        [string]$EnvPath
    )
    $rootUrl = Get-ApiRoot $Base
    $computer = $env:COMPUTERNAME
    $role = ([string]$EnvMap['SCANNER_ROLE']).Trim()
    if (-not $role) { $role = 'portable' }
    $name = ([string]$EnvMap['SCANNER_NAME']).Trim()
    if (-not $name) { $name = "Laptop-$computer" }
    $sid = ([string]$EnvMap['SCANNER_ID']).Trim()
    Write-Host ("[OK] Binding laptop scanner '{0}' to the emailed access token." -f $name)
    $body = @{
        token = $ClientToken
        name = $name
        scanner_role = $role
    }
    if ($sid) { $body.scanner_id = $sid }
    $bound = Invoke-JsonApi -Method 'POST' -Url ($rootUrl + '/api/scanners/bind-client-token') -Tenant $Tenant -AccessToken $AccessToken -BodyObject $body -VerifyTls $VerifyTls
    if ($bound.Status -eq 403) {
        throw 'Logged-in user cannot manage scanners (needs scan:policy_manage). Use a firm admin account.'
    }
    if ($bound.Status -lt 200 -or $bound.Status -ge 300) {
        if ($bound.Status -lt 0 -and -not [string]::IsNullOrWhiteSpace([string]$bound.Error)) {
            throw "Scanner binding network/TLS failure: $($bound.Error)"
        }
        $detail = Get-ApiErrorText $bound
        if ($detail) { throw "Could not bind the emailed token to this laptop (HTTP $($bound.Status)): $detail" }
        throw "Could not bind the emailed token to this laptop (HTTP $($bound.Status))"
    }
    $json = ConvertFrom-JsonSafe $bound.Body
    $token = [string]$json.agent_token
    if (-not $token) { $token = $ClientToken }
    $newId = [string]$json.id
    if ($newId -and $EnvPath) { Set-DotEnvValue -Path $EnvPath -Key 'SCANNER_ID' -Value $newId }
    return $token
}

function Get-BootstrapComposeFile([string]$Root) {
    foreach ($name in @('docker-compose.yml','docker-compose.yaml','compose.yml','compose.yaml')) {
        $candidate = Join-Path $Root $name
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw "Docker Compose file not found under $Root"
}

$script:AetherisBootstrapImageReady = $false

function Invoke-DockerBootstrapJson {
    param(
        [string]$Root,
        [ValidateSet('preflight','bind','inspect-cert')][string]$Mode,
        [string]$Base,
        [string]$Tenant,
        [bool]$VerifyTls = $true,
        [string]$ScannerName = '',
        [string]$ScannerRole = 'portable',
        [string]$ScannerId = '',
        [string]$InputSecret = ''
    )
    $compose = Get-BootstrapComposeFile $Root
    if (-not $script:AetherisBootstrapImageReady) {
        Write-Host '[INFO] Preparing Linux/OpenSSL bootstrap helper (Docker cache is reused).' -ForegroundColor DarkGray
        $old = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $buildOut = @(& docker.exe compose -f $compose --profile bootstrap build scanner-bootstrap 2>&1)
            $buildCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $old
        }
        if ($buildCode -ne 0) {
            $text = (@($buildOut | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
            throw "Could not build scanner-bootstrap helper (exit $buildCode).`n$text"
        }
        $script:AetherisBootstrapImageReady = $true
    }

    $verifyValue = if ($VerifyTls) { 'true' } else { 'false' }
    $args = @(
        'compose','-f',$compose,'--profile','bootstrap','run','--rm','--no-deps','-T',
        'scanner-bootstrap',$Mode,
        '--base-url',$Base,
        '--tenant',$Tenant,
        '--verify-tls',$verifyValue
    )
    if ($Mode -eq 'bind') {
        $args += @('--scanner-name',$ScannerName,'--scanner-role',$ScannerRole)
        if (-not [string]::IsNullOrWhiteSpace($ScannerId)) { $args += @('--scanner-id',$ScannerId) }
    }

    $old = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ($Mode -eq 'bind') {
            $output = @(($InputSecret + [Environment]::NewLine) | & docker.exe @args 2>&1)
        } else {
            $output = @(& docker.exe @args 2>&1)
        }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $old
    }

    $lines = @($output | ForEach-Object { $_.ToString() })
    $marker = 'AETHERIS_BOOTSTRAP_RESULT='
    $hit = $lines | Where-Object { $_.StartsWith($marker) } | Select-Object -Last 1
    if (-not $hit) {
        $safe = ($lines -join [Environment]::NewLine)
        if ($safe.Length -gt 3000) { $safe = $safe.Substring([Math]::Max(0,$safe.Length-3000)) }
        throw "Docker TLS bootstrap helper did not return a result (exit $code).`n$safe"
    }
    try {
        $encoded = $hit.Substring($marker.Length)
        $bytes = [Convert]::FromBase64String($encoded.Replace('-','+').Replace('_','/'))
        $jsonText = [Text.Encoding]::UTF8.GetString($bytes)
        return ($jsonText | ConvertFrom-Json)
    } catch {
        throw "Could not decode Docker bootstrap result: $($_.Exception.Message)"
    }
}

function Format-BootstrapFailure($Result) {
    $parts = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Result) { return 'Unknown Docker bootstrap failure.' }
    $stage = [string]$Result.stage
    $status = [string]$Result.status
    $error = [string]$Result.error
    if ($stage) { $parts.Add("stage=$stage") }
    if ($status) { $parts.Add("HTTP=$status") }
    if ($error) { $parts.Add($error) }
    $cert = $Result.certificate
    if ($null -ne $cert) {
        if ([string]$cert.subject) { $parts.Add("Certificate subject: $([string]$cert.subject)") }
        if ($cert.san_dns) { $parts.Add("Certificate DNS SAN: $(@($cert.san_dns) -join ', ')") }
        if ($cert.san_ip) { $parts.Add("Certificate IP SAN: $(@($cert.san_ip) -join ', ')") }
        if ([string]$cert.error) { $parts.Add("Certificate probe: $([string]$cert.error)") }
    }
    $hint = $Result.http_redirect_hint
    if ($null -ne $hint -and [string]$hint.location) {
        $parts.Add("HTTP redirect suggests: $([string]$hint.location)")
    }
    return ($parts -join [Environment]::NewLine)
}

function Sync-LaptopAgentToken {
    param(
        [string]$Root,
        [string]$EnvPath,
        [hashtable]$EnvMap
    )
    $central = ([string]$EnvMap['CENTRAL_API_URL']).Trim().TrimEnd('/')
    $retiredCentral = 'https://122.179.141.248'
    $liveCentral = 'https://future-softtech.co.in'
    try { $centralHost = ([Uri]$central).Host } catch { $centralHost = '' }
    if ($centralHost -eq '122.179.141.248') {
        Write-Host ("[INFO] {0} is no longer the Aetheris server. That address answers HTTP 200 with status 501 and does not return an access token. Using {1}." -f $retiredCentral, $liveCentral) -ForegroundColor Yellow
        $central = $liveCentral
        Set-DotEnvValue -Path $EnvPath -Key 'CENTRAL_API_URL' -Value $central
        $EnvMap['CENTRAL_API_URL'] = $central
    }
    $tenant = ([string]$EnvMap['TENANT_SLUG']).Trim()
    if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = 'aetheris' }
    $verifyTls = Get-VerifyTls $EnvMap

    Write-Host '[INFO] Control-plane TLS transport: Linux Docker + OpenSSL (Windows Schannel/SSPI bypassed).' -ForegroundColor Cyan
    $pre = Invoke-DockerBootstrapJson -Root $Root -Mode 'preflight' -Base $central -Tenant $tenant -VerifyTls $verifyTls
    if (-not [bool]$pre.ok) {
        $detail = Format-BootstrapFailure $pre
        throw "Central HTTPS preflight failed inside Linux Docker.`n$detail`nKeep VERIFY_TLS=true. If the certificate SAN shows a DNS name, set CENTRAL_API_URL to that HTTPS DNS name."
    }
    $canonical = ([string]$pre.canonical_url).Trim().TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($canonical)) { throw 'Docker bootstrap did not return canonical_url.' }
    if ($canonical -ne $central) {
        Write-Host ("[OK] Central redirect resolved: {0} -> {1}" -f $central, $canonical) -ForegroundColor Green
        Set-DotEnvValue -Path $EnvPath -Key 'CENTRAL_API_URL' -Value $canonical
        $EnvMap['CENTRAL_API_URL'] = $canonical
        $central = $canonical
    }
    Write-Host ("[INFO] Central reachable at {0} (HTTP {1}, transport={2}). Asking for the emailed access token." -f $central, [string]$pre.status, [string]$pre.transport)

    $clientToken = Get-ClientAccessTokenPrompt -Tenant $tenant
    $tokenTenant = Get-AccessTokenTenant $clientToken
    if ($tokenTenant -and $tokenTenant -ne $tenant.ToLowerInvariant()) {
        Write-Host ("[INFO] This access token is for organization {0}. This laptop was set to {1}, so login was rejected. Using {0}." -f $tokenTenant, $tenant) -ForegroundColor Yellow
        $tenant = $tokenTenant
        Set-DotEnvValue -Path $EnvPath -Key 'TENANT_SLUG' -Value $tenant
        $EnvMap['TENANT_SLUG'] = $tenant
    }
    $computer = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($computer)) { $computer = 'CLIENT' }
    $role = ([string]$EnvMap['SCANNER_ROLE']).Trim()
    if (-not $role) { $role = 'portable' }
    $name = ([string]$EnvMap['SCANNER_NAME']).Trim()
    if (-not $name) { $name = "Laptop-$computer" }
    $sid = ([string]$EnvMap['SCANNER_ID']).Trim()

    Write-Host ("[INFO] Signing in and binding scanner '{0}' using Docker/OpenSSL." -f $name)
    $bound = Invoke-DockerBootstrapJson -Root $Root -Mode 'bind' -Base $central -Tenant $tenant -VerifyTls $verifyTls -ScannerName $name -ScannerRole $role -ScannerId $sid -InputSecret $clientToken
    $clientToken = $null
    if (-not [bool]$bound.ok) {
        $detail = Format-BootstrapFailure $bound
        throw "Scanner token login/binding failed inside Linux Docker.`n$detail"
    }
    $token = ([string]$bound.agent_token).Trim()
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'Central binding succeeded but no agent token was returned.' }
    $newId = ([string]$bound.scanner_id).Trim()
    if ($newId) {
        Set-DotEnvValue -Path $EnvPath -Key 'SCANNER_ID' -Value $newId
        $EnvMap['SCANNER_ID'] = $newId
    }
    Save-AgentToken -Root $Root -EnvPath $EnvPath -Token $token
    Write-Host '[OK] Token login, scanner binding, and heartbeat validation succeeded through Linux/OpenSSL.' -ForegroundColor Green
    Write-Host '[OK] Laptop scanner is linked with the same emailed token used on the web UIs.' -ForegroundColor Green
    return $token
}
