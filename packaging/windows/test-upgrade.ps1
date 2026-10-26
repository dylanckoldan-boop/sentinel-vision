# Upgrade from a previous release that already has the protection service (0.4.x) to the new build, on a clean
# Windows machine (run by .github/workflows/release.yml as admin). Checks that the service is replaced and running,
# protected data (quarantine, rollback vault, settings) carries over, and the result uninstalls cleanly.
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [Parameter(Mandatory = $true)][string]$NewVersion,
    [string]$PreviousVersion = '0.4.0',
    [string]$Repo = 'dylanckoldan-boop/sentinel-vision'
)
$ErrorActionPreference = 'Stop'
$script:passed = 0
function Progress([string]$m) { Write-Host "== $m"; Add-Content -LiteralPath progress.txt -Value "$(Get-Date -Format HH:mm:ss) $m" }
function Assert($cond, $msg) { if (-not $cond) { throw "ASSERTION FAILED: $msg" } else { $script:passed++; Write-Host "OK  $msg" } }
function Invoke-Setup([string]$exe, [string[]]$arguments, [string]$label) {
    $proc = Start-Process $exe -ArgumentList $arguments -PassThru
    $null = $proc.Handle
    if (-not $proc.WaitForExit(600000)) { throw "$label did not finish within 10 minutes" }
    if ($proc.ExitCode -ne 0) { throw "$label exit code $($proc.ExitCode)" }
    Write-Host "OK  $label finished"
}
$app = Join-Path $env:ProgramFiles 'Sentinel Vision'
function SvCli([string[]]$a) { $out = & "$app\sentinel-vision-cli.exe" @a 2>&1 | Out-String; Write-Host $out; return $out }
function Service-State { (Get-CimInstance Win32_Service -Filter "Name='SentinelVisionService'") }
$docs = [Environment]::GetFolderPath('MyDocuments')
New-Item -ItemType Directory -Force $docs | Out-Null

Progress "previous release $PreviousVersion"
$prev = Join-Path $env:RUNNER_TEMP "SentinelVision-$PreviousVersion-Setup.exe"
$base = "https://github.com/$Repo/releases/download/v$PreviousVersion"
Invoke-WebRequest "$base/SentinelVision-$PreviousVersion-Setup.exe" -OutFile $prev
$sumsFile = Join-Path $env:RUNNER_TEMP 'prev-SHA256SUMS.txt'
Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile $sumsFile
$name = "SentinelVision-$PreviousVersion-Setup.exe"
$lines = @(Get-Content $sumsFile | Where-Object { ($_ -split '\s+', 2)[1] -replace '^\*', '' -eq $name })
Assert ($lines.Count -eq 1 -and (Get-FileHash $prev -Algorithm SHA256).Hash -eq ([string]$lines[0] -split '\s+')[0].ToUpper()) "previous release matches its published SHA-256"
Invoke-Setup $prev @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS="autostart"', '/LOG="prev-install.log"') "previous release install"
Assert ((Service-State).State -eq 'Running') "previous release's protection service running"
Assert ((SvCli @('--version')) -match [regex]::Escape($PreviousVersion)) "previous version installed"

# data in the previous version's protected storage
foreach ($i in 1..3) { Set-Content -Path "$docs\Plan $i.txt" -Value ("Plan $i`n" * 200) }
$rules = Join-Path $env:LOCALAPPDATA 'SentinelVision\rules\custom'
New-Item -ItemType Directory -Force $rules | Out-Null
Set-Content -Path "$rules\svtest.yar" -Value 'rule SVTest_Marker { meta: severity = "critical" strings: $a = "SV-UPGRADE-TEST-MARKER-51d0" condition: $a }'
$samples = Join-Path $env:RUNNER_TEMP 'samples'
New-Item -ItemType Directory -Force $samples | Out-Null
Set-Content -Path "$samples\marked.bin" -Value 'payload SV-UPGRADE-TEST-MARKER-51d0 payload'
SvCli @('scan', $samples) | Out-Null
Assert (-not (Test-Path "$samples\marked.bin")) "previous release quarantined the test file"
$gui = Start-Process "$app\SentinelVision.exe" -ArgumentList '--minimized' -PassThru
Start-Sleep -Seconds 25
Assert ((SvCli @('rollback', 'list')) -match 'Plan 1\.txt') "previous release has documents in its protected vault"
Assert ((SvCli @('service')) -match 'quarantine:\s+1 item') "previous release has the quarantined file in protected storage"

Progress "upgrade to the new build (app and service running)"
Invoke-Setup $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG="upgrade.log"') "upgrade from $PreviousVersion"
$svc = Service-State
Assert ($svc.State -eq 'Running' -and $svc.StartName -eq 'LocalSystem') "protection service replaced and running"
$st = SvCli @('service')
Assert ($st -match [regex]::Escape("service $NewVersion running")) "the new service version is running ($st)"
Assert ($st -match 'quarantine:\s+1 item') "quarantine carried over"
Assert ((SvCli @('rollback', 'list')) -match 'Plan 1\.txt') "rollback vault carried over"
Assert ($st -match 'firewall:\s+on') "firewall blocking still on"
$run = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).SentinelVision
Assert ($run -like "*$app\SentinelVision.exe*") "start-at-sign-in kept"
$self = SvCli @('service', '--self-test')
Assert ($self -match 'administrator rights|Tamper protection: OK') "tamper protection self-test runs"
Assert ((SvCli @('plugins')) -match 'Plugins are loaded from: .*plugins') "plugin folder is the protected one in Program Files"

Progress "uninstall"
Invoke-Setup "$app\unins000.exe" @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') "uninstaller"
$deadline = (Get-Date).AddSeconds(90)
while ((Test-Path "$app\SentinelVision.exe") -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
Assert ($null -eq (Service-State)) "protection service removed"
Assert (-not (Test-Path "$app\SentinelVision.exe")) "program removed"
Write-Host "::notice title=Windows upgrade test::$script:passed checks passed: upgrade from $PreviousVersion with the protection service, data carried over, uninstall"
