param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
. (Join-Path $ProjectRoot 'script_docker/start_docker.lib.ps1')
$script:checks=0
function Assert-Https([bool]$Value,[string]$Message) {
    if (-not $Value) { throw "FAIL: $Message" }
    $script:checks++
}
$script:events=New-Object System.Collections.Generic.List[object]
$script:bindings='public';$script:failure=''
function Invoke-Docker {
    param([string]$Title,[string[]]$DockerArgs)
    $script:events.Add([pscustomobject]@{Kind='docker';Args=$DockerArgs;Title=$Title})
    if (($script:failure -eq 'remove' -and $DockerArgs -contains 'rm') -or
        ($script:failure -eq 'up' -and $DockerArgs -contains 'up')) { throw 'Simulated Docker failure' }
}
function Get-DockerJson {
    param([string[]]$DockerArgs)
    $script:events.Add([pscustomobject]@{Kind='inspect';Args=$DockerArgs})
    if ($DockerArgs -contains 'ps') {
        if ($script:bindings -eq 'missing') { return [pscustomobject]@{ID=''} }
        return [pscustomobject]@{ID='test-gateway'}
    }
    $ip=if ($script:bindings -eq 'loopback') {'127.0.0.1'} else {'0.0.0.0'}
    $port=if ($script:bindings -eq 'wrong-port') {'8443'} else {'443'}
    $ports=[pscustomobject]@{'80/tcp'=@([pscustomobject]@{HostIp=$ip;HostPort='80'});
        '443/tcp'=@([pscustomobject]@{HostIp=$ip;HostPort=$port})}
    return [pscustomobject]@{State=[pscustomobject]@{Running=($script:bindings -ne 'stopped')};NetworkSettings=[pscustomobject]@{Ports=$ports}}
}
function Invoke-CertificateTool {
    param([string[]]$ComposeArgs,[string[]]$ToolArgs)
    $script:events.Add([pscustomobject]@{Kind='probe';Args=$ToolArgs})
    if ($script:failure -eq 'tls') { throw 'SAN/trust failure' }
    return [pscustomobject]@{trusted=$true}
}
$argsForGateway=@('compose','--project-name','aetheris-gateway','-f','public.yml')
foreach ($domain in @('', 'example.org')) {
    $script:events.Clear()
    Start-PublicHttpsGateway -ComposeArgs $argsForGateway -PublicIP 8.8.8.8 -Domain $domain
    Assert-Https ($script:events[0].Args -contains 'rm' -and $script:events[0].Args[-1] -eq 'acme-bootstrap') 'Owned stale bootstrap is released first'
    Assert-Https ($script:events[0].Args -contains 'aetheris-gateway') 'Bootstrap removal remains project-scoped'
    Assert-Https ($script:events[1].Args -contains 'up' -and $script:events[1].Args -contains 'gateway' -and $script:events[1].Args -contains 'certbot-renewer') 'Gateway and renewal start together'
    Assert-Https ($script:events[1].Args -contains '--wait' -and $script:events[1].Args -contains '--no-build') 'Edge health is required and compiled image reused'
    $probes=@($script:events | Where-Object Kind -eq 'probe')
    Assert-Https ($probes.Count -eq $(if($domain){2}else{1})) 'IP-only and IP/domain profiles probe exactly their identities'
    Assert-Https ($probes[0].Args[-1] -eq '8.8.8.8') 'Public IP certificate identity is checked'
    if ($domain) { Assert-Https ($probes[1].Args[-1] -eq $domain) 'Domain certificate is checked separately' }
}
foreach ($mode in @('loopback','wrong-port','missing','stopped')) {
    $script:bindings=$mode;$failed=$false
    try { Assert-PublicGatewayBindings -ComposeArgs $argsForGateway } catch {$failed=$true}
    Assert-Https $failed "Reject unusable public gateway binding: $mode"
}
$script:bindings='public'
foreach ($failure in @('remove','up','tls')) {
    $script:failure=$failure;$script:events.Clear();$failed=$false
    try { Start-PublicHttpsGateway -ComposeArgs $argsForGateway -PublicIP 8.8.8.8 } catch {$failed=$true}
    Assert-Https $failed "Handoff failure cannot report ready: $failure"
    if ($failure -eq 'remove') { Assert-Https ($script:events.Count -eq 1) 'Port release failure never starts gateway' }
    if ($failure -eq 'up') { Assert-Https (@($script:events | Where-Object Kind -eq 'probe').Count -eq 0) 'Failed gateway startup never reports trusted TLS' }
}
$entry=[IO.File]::ReadAllText((Join-Path $ProjectRoot 'script_docker/start_docker.ps1'))
Assert-Https ($entry.IndexOf('Start-PublicHttpsGateway -ComposeArgs') -lt $entry.IndexOf('"Start all product stacks')) 'Public edge starts before optional product readiness can fail'
Assert-Https ($entry -match 'if \(-not \$isPublic\).*?') 'Local gateway path remains separate'
Assert-Https ($entry -match 'HTTPS gateway and certificate renewal remain running') 'Product failure explains partial readiness'
foreach ($file in @('script_docker/start_docker.ps1','script_docker/start_docker.lib.ps1','tests/windows_public_https_handoff_checks.ps1')) {
    $tokens=$null;$errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ProjectRoot $file),[ref]$tokens,[ref]$errors)
    Assert-Https ($errors.Count -eq 0) "PowerShell parses: $file"
}
Write-Host "PASS: $script:checks HTTPS handoff/binding checks with offline Docker/TLS mocks."
