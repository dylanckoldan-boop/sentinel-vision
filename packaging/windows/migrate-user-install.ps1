# Removes a Sentinel Vision 0.3.x installed in the user's own folder, after the new version was installed in
# Program Files. Run by the installer as the ORIGINAL (not elevated) user, so it only touches that user's own files
# and registry, and nothing in the old (user-writable) folder is ever run with administrator rights.
# Keeps: the user's data folder (the app moves the vault and quarantine into the protected service on its first
# start) and the user's start-at-sign-in choice (pointed at the new location).
param(
    [Parameter(Mandatory = $true)][string]$NewDir,
    [string]$AppId = '{9D3C2B71-6A4E-4F0B-9E57-2C1A8D4B5E60}'
)
$ErrorActionPreference = 'Continue'
$NewDir = $NewDir.TrimEnd('\')
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$($AppId)_is1"
if (-not (Test-Path -LiteralPath $key)) { Write-Output 'no per-user install found'; exit 0 }

$old = (Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue).InstallLocation
if ($old) { $old = $old.TrimEnd('\') }
$inProfile = $old -and ($old.StartsWith($env:LOCALAPPDATA, 'OrdinalIgnoreCase') -or
                        $old.StartsWith($env:USERPROFILE, 'OrdinalIgnoreCase'))
if ($old -and $inProfile -and ($old -ne $NewDir) -and (Test-Path -LiteralPath $old)) {
    for ($i = 0; $i -lt 10 -and (Test-Path -LiteralPath $old); $i++) {
        Remove-Item -LiteralPath $old -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $old) { Start-Sleep -Milliseconds 500 }
    }
}
Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue

# the per-user PATH entry of the old command-line tool
$envKey = 'HKCU:\Environment'
$path = (Get-ItemProperty -LiteralPath $envKey -Name Path -ErrorAction SilentlyContinue).Path
if ($path -and $old) {
    $kept = ($path -split ';' | Where-Object { $_ -and ($_.TrimEnd('\') -ne $old) }) -join ';'
    if ($kept -ne $path) { Set-ItemProperty -LiteralPath $envKey -Name Path -Value $kept -Type ExpandString }
}

# the old shortcuts (the new version has its own for all users)
$desktop = [Environment]::GetFolderPath('Desktop')
foreach ($lnk in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Sentinel Vision.lnk", "$desktop\Sentinel Vision.lnk")) {
    if (Test-Path -LiteralPath $lnk) { Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue }
}

# start at sign-in: keep the choice, pointing at the new location
$run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$value = (Get-ItemProperty -LiteralPath $run -Name SentinelVision -ErrorAction SilentlyContinue).SentinelVision
if ($value) {
    Set-ItemProperty -LiteralPath $run -Name SentinelVision -Value ('"' + (Join-Path $NewDir 'SentinelVision.exe') + '" --minimized')
}
Write-Output "moved from $old to $NewDir"
exit 0
