# Frees host ports that the next `docker compose up` needs.
# A stopped container can still reserve 127.0.0.1:6389 inside Docker after
# netstat shows the port as free. Remove that container (not its volume).
# If a normal Windows process is listening, stop that process.

$script:ComposePortConfigCache = @{}

function Get-ComposeConfigObject {
    param(
        [Parameter(Mandatory = $true)][string]$Docker,
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs
    )
    $key = ($ComposeArgs -join " ")
    if ($script:ComposePortConfigCache.ContainsKey($key)) {
        return $script:ComposePortConfigCache[$key]
    }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $json = & $Docker @ComposeArgs "config" "--format" "json" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $json) { return $null }
        $text = if ($json -is [array]) { $json -join "`n" } else { [string]$json }
        $obj = $text | ConvertFrom-Json
        $script:ComposePortConfigCache[$key] = $obj
        return $obj
    }
    catch {
        return $null
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

function Get-ServiceNamesForPorts {
    param(
        $Config,
        [string[]]$Services
    )
    $known = @($Config.services.PSObject.Properties.Name)
    $wanted = New-Object System.Collections.Generic.List[string]
    $pending = New-Object System.Collections.Generic.Queue[string]
    foreach ($name in @($Services)) {
        if ($known -contains $name) {
            $wanted.Add($name)
            $pending.Enqueue($name)
        }
    }
    while ($pending.Count -gt 0) {
        $name = $pending.Dequeue()
        $svc = $Config.services.$name
        $deps = @()
        if ($svc.depends_on -is [string]) {
            $deps = @($svc.depends_on)
        }
        elseif ($svc.depends_on -is [System.Array]) {
            $deps = @($svc.depends_on)
        }
        elseif ($svc.depends_on) {
            $deps = @($svc.depends_on.PSObject.Properties.Name)
        }
        foreach ($dep in $deps) {
            if ($dep -and ($known -contains $dep) -and ($wanted -notcontains $dep)) {
                $wanted.Add($dep)
                $pending.Enqueue($dep)
            }
        }
    }
    return @($wanted)
}

function Get-PublishedHostPorts {
    param(
        $Config,
        [string[]]$Services
    )
    $names = @(Get-ServiceNamesForPorts -Config $Config -Services $Services)
    $ports = New-Object System.Collections.Generic.List[int]
    foreach ($name in $names) {
        foreach ($entry in @($Config.services.$name.ports)) {
            if (-not $entry) { continue }
            $published = "$($entry.published)"
            if ($published -match '^\d+$') {
                $ports.Add([int]$published)
            }
        }
    }
    return @($ports | Sort-Object -Unique)
}

function Get-DockerPortHolders {
    param([Parameter(Mandatory = $true)][string]$Docker)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $ids = @(& $Docker ps -aq 2>$null | Where-Object { $_ })
        if (-not $ids -or @($ids).Count -eq 0) { return @() }
        $raw = & $Docker inspect @ids 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return @() }
        $text = if ($raw -is [array]) { $raw -join "`n" } else { [string]$raw }
        $parsed = $text | ConvertFrom-Json
        $items = foreach ($item in $parsed) { $item }
    }
    finally {
        $ErrorActionPreference = $prev
    }
    $holders = @()
    foreach ($item in $items) {
        if (-not $item.HostConfig.PortBindings) { continue }
        $project = ""
        $service = ""
        if ($item.Config.Labels) {
            $project = [string]$item.Config.Labels.'com.docker.compose.project'
            $service = [string]$item.Config.Labels.'com.docker.compose.service'
        }
        $ports = New-Object System.Collections.Generic.List[int]
        foreach ($prop in @($item.HostConfig.PortBindings.PSObject.Properties)) {
            foreach ($bind in @($prop.Value)) {
                if ("$($bind.HostPort)" -match '^\d+$') { $ports.Add([int]$bind.HostPort) }
            }
        }
        if ($ports.Count -eq 0) { continue }
        $holders += [pscustomobject]@{
            Id      = [string]$item.Id
            Name    = [string]$item.Name.TrimStart("/")
            Status  = [string]$item.State.Status
            Project = $project
            Service = $service
            Ports   = @($ports | Sort-Object -Unique)
        }
    }
    return @($holders)
}

function Stop-PortListener {
    param([Parameter(Mandatory = $true)][int]$Port)
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    foreach ($listener in $listeners) {
        $proc = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        if ($proc.ProcessName -match '^(docker|dockerd|vpnkit|wsl|wslservice|wslrelay|com\.docker)') {
            Write-Host "Port $Port is held by $($proc.ProcessName) (pid $($proc.Id)). The Docker engine is left running." -ForegroundColor Yellow
            continue
        }
        Write-Host "Port $Port is in use by $($proc.ProcessName) (pid $($proc.Id)). Stopping that process." -ForegroundColor Yellow
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        }
        catch {
            Write-Host "Could not stop pid $($proc.Id) on port ${Port}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Clear-OccupiedHostPorts {
    param(
        [Parameter(Mandatory = $true)][string]$Docker,
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs,
        [string[]]$Services = @(),
        [switch]$IncludeRunning
    )
    if (-not $Services -or $Services.Count -eq 0) { return }
    $config = Get-ComposeConfigObject -Docker $Docker -ComposeArgs $ComposeArgs
    if (-not $config -or -not $config.services) {
        Write-Host "Could not read compose ports for $($Services -join ', '). Continuing." -ForegroundColor Yellow
        return
    }
    $project = ""
    for ($i = 0; $i -lt $ComposeArgs.Count; $i++) {
        if ($ComposeArgs[$i] -eq "--project-name" -and ($i + 1) -lt $ComposeArgs.Count) {
            $project = $ComposeArgs[$i + 1]
        }
    }
    $keep = @(Get-ServiceNamesForPorts -Config $config -Services $Services)
    $holders = @(Get-DockerPortHolders -Docker $Docker)
    foreach ($port in @(Get-PublishedHostPorts -Config $config -Services $Services)) {
        foreach ($holder in @($holders | Where-Object { $_.Ports -contains $port })) {
            $sameService = $holder.Project -eq $project -and ($keep -contains $holder.Service)
            if ($holder.Status -eq "running" -and $sameService -and -not $IncludeRunning) { continue }
            Write-Host "Port $port is reserved by $($holder.Name) ($($holder.Status)). Removing that container so it can be started cleanly." -ForegroundColor Yellow
            & $Docker rm -f $holder.Id | Out-Null
        }
        Stop-PortListener -Port $port
    }
}
