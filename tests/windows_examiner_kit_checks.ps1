param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonExe = 'python'
)
$ErrorActionPreference = 'Stop'
$file = Join-Path $ProjectRoot 'scripts/ensure-examiner-kit.ps1'
$tokens=$null; $parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$function=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-KitNative'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$script:checks=0
function Assert-Kit([bool]$Value,[string]$Message) {
    if (-not $Value) { throw "FAIL: $Message" }
    $script:checks++
}
$script:mode='success';$script:calls=New-Object System.Collections.Generic.List[object]
function MockKitPython {
    $call=@($args);$script:calls.Add($call)
    if ($call -notcontains '--no-cache-dir') {
        $global:LASTEXITCODE=1
        Write-Error 'Permission denied: user pip cache wheels/hexdump.whl'
        return
    }
    if (($script:mode -eq 'upgrade-fail' -and $call -contains '--upgrade') -or
        ($script:mode -eq 'requirements-fail' -and $call -contains '-r')) {
        $global:LASTEXITCODE=1
        Write-Error 'Installer download failed'
        return
    }
    Write-Error 'Healthy pip progress on stderr'
    $global:LASTEXITCODE=0
}
# Execute the actual production pip calls, with a cache-denied fake interpreter.
$commands=@($ast.FindAll({param($n)
    $n -is [System.Management.Automation.Language.CommandAst] -and
    $n.GetCommandName() -eq 'Invoke-KitNative' -and $n.Extent.Text -match '"pip", "install"'
},$true))
Assert-Kit ($commands.Count -eq 2) 'Upgrade and requirements installer calls are present'
$install=[scriptblock]::Create(($commands | ForEach-Object {$_.Extent.Text}) -join "`n")
$venvPy='MockKitPython';$reqFile='E:\project with spaces\tools\host-python-requirements.txt'
& $install
Assert-Kit ($script:calls.Count -eq 2) 'Both steps succeed when the default cache is inaccessible'
Assert-Kit ($script:calls[0] -contains '--no-cache-dir' -and $script:calls[1] -contains '--no-cache-dir') 'Both steps bypass user wheel cache'
Assert-Kit ($script:calls[1][-1] -eq $reqFile) 'Requirements path with spaces remains one argument'
Assert-Kit ($ErrorActionPreference -eq 'Stop') 'Healthy stderr restores error preference'
$script:mode='upgrade-fail';$script:calls.Clear();$failed=$false
try { & $install } catch { $failed=$_.Exception.Message -match 'Upgrading host-python pip failed' }
Assert-Kit $failed 'Pip upgrade failure is reported by step'
Assert-Kit ($script:calls.Count -eq 1) 'Requirements do not run after failed pip upgrade'
Assert-Kit ($ErrorActionPreference -eq 'Stop') 'Installer failure restores error preference'
$script:mode='requirements-fail';$script:calls.Clear();$failed=$false
try { & $install } catch { $failed=$_.Exception.Message -match 'Installing host-python requirements failed' }
Assert-Kit ($failed -and $script:calls.Count -eq 2) 'Requirements failure stops setup'
# Native smoke checks exercise the helper with a real executable (no pip/network).
Invoke-KitNative -Exe $PythonExe -Arguments @('-c','import sys; print("healthy warning", file=sys.stderr)') -Step 'Native warning test'
Assert-Kit ($ErrorActionPreference -eq 'Stop') 'Real native stderr is not a failed command'
$failed=$false
try { Invoke-KitNative -Exe $PythonExe -Arguments @('-c','import sys; sys.exit(7)') -Step 'Native exit test' } catch {
    $failed=$_.Exception.Message -match 'exit 7'
}
Assert-Kit $failed 'Real native nonzero exit is propagated'
$global:LASTEXITCODE=0;$failed=$false
try { Invoke-KitNative -Exe 'nonexistent-examiner-test-executable' -Step 'Missing executable' } catch { $failed=$true }
Assert-Kit $failed 'Missing executable cannot reuse stale success'
Assert-Kit ($ErrorActionPreference -eq 'Stop') 'Missing executable preserves caller preference'
Write-Host "PASS: $script:checks examiner-kit checks (cache-denied simulation and real native smoke checks)."
