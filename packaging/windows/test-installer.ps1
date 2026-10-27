# Windows installer lifecycle test (run by .github/workflows/release.yml on a clean Windows machine, as admin).
#
#  1. installs the PREVIOUS release (0.3.x, per-user, in the user's own folder) and gives it data: a quarantined
#     file and documents in the rollback vault;
#  2. upgrades to the new build and checks: Program Files, old copy removed, service installed and running as
#     LocalSystem, protected data folder, data carried over, start-at-sign-in kept;
#  3. from an ordinary (non-administrator) account: can't delete or list the protected data, can't replace the
#     program, can't weaken protection, can't see another account's vault;
#  4. upgrade over the running app and service, self-update relaunch, option change;
#  5. silent uninstall: service, firewall/hosts blocking, files, shortcuts, PATH, decoys all removed.
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [string]$PreviousVersion = '0.3.1',
    [string]$Repo = 'dylanckoldan-boop/sentinel-vision'
)
$ErrorActionPreference = 'Stop'
$script:passed = 0
function Progress([string]$m) { Write-Host "== $m"; Add-Content -LiteralPath progress.txt -Value "$(Get-Date -Format HH:mm:ss) $m" }
function Assert($cond, $msg) { if (-not $cond) { throw "ASSERTION FAILED: $msg" } else { $script:passed++; Write-Host "OK  $msg" } }
function Invoke-Setup([string]$exe, [string[]]$arguments, [string]$label) {
    # Start-Process -Wait would also wait for programs the installer starts (the app), so wait for the installer only
    $proc = Start-Process $exe -ArgumentList $arguments -PassThru
    $null = $proc.Handle
    if (-not $proc.WaitForExit(600000)) { throw "$label did not finish within 10 minutes" }
    if ($proc.ExitCode -ne 0) { throw "$label exit code $($proc.ExitCode)" }
    Write-Host "OK  $label finished"
}
function SvCli([string[]]$a) { $out = & "$newApp\sentinel-vision-cli.exe" @a 2>&1 | Out-String; Write-Host $out; return $out }
function Service-State { (Get-CimInstance Win32_Service -Filter "Name='SentinelVisionService'") }

$oldApp = Join-Path $env:LOCALAPPDATA 'Programs\Sentinel Vision'
$newApp = Join-Path $env:ProgramFiles 'Sentinel Vision'
$data = Join-Path $env:ProgramData 'SentinelVision\Service'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$uninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{9D3C2B71-6A4E-4F0B-9E57-2C1A8D4B5E60}_is1'
$docs = [Environment]::GetFolderPath('MyDocuments')
New-Item -ItemType Directory -Force $docs | Out-Null

# ------------------------------------------------------------------------------------------------ 1. previous release
Progress "previous release $PreviousVersion (per-user install)"
$prev = Join-Path $env:RUNNER_TEMP "SentinelVision-$PreviousVersion-Setup.exe"
$base = "https://github.com/$Repo/releases/download/v$PreviousVersion"
Invoke-WebRequest "$base/SentinelVision-$PreviousVersion-Setup.exe" -OutFile $prev
$sumsFile = Join-Path $env:RUNNER_TEMP 'prev-SHA256SUMS.txt'
Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile $sumsFile
$name = "SentinelVision-$PreviousVersion-Setup.exe"
$lines = @(Get-Content $sumsFile | Where-Object { ($_ -split '\s+', 2)[1] -replace '^\*', '' -eq $name })
Assert ($lines.Count -eq 1) "previous release checksum list has exactly one entry for $name"
$expected = ([string]$lines[0] -split '\s+')[0]
Assert ((Get-FileHash $prev -Algorithm SHA256).Hash -eq $expected.ToUpper()) "previous release download matches its published SHA-256"
Invoke-Setup $prev @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', '/TASKS="autostart,addtopath"', '/LOG="prev-install.log"') "previous release install"
Assert (Test-Path "$oldApp\SentinelVision.exe") "previous release installed in the user folder"

# data: documents for the rollback vault, and a file the old version quarantines (custom rule, harmless content)
foreach ($i in 1..3) { Set-Content -Path "$docs\Report $i.txt" -Value ("Quarterly report $i`n" * 200) }
$rules = Join-Path $env:LOCALAPPDATA 'SentinelVision\rules\custom'
New-Item -ItemType Directory -Force $rules | Out-Null
Set-Content -Path "$rules\svtest.yar" -Value 'rule SVTest_Marker { meta: severity = "critical" strings: $a = "SV-INSTALLER-TEST-MARKER-9f3c" condition: $a }'
$samples = Join-Path $env:RUNNER_TEMP 'samples'
New-Item -ItemType Directory -Force $samples | Out-Null
Set-Content -Path "$samples\marked.bin" -Value 'payload SV-INSTALLER-TEST-MARKER-9f3c payload'
& "$oldApp\sentinel-vision-cli.exe" scan $samples | Out-Host
Assert (-not (Test-Path "$samples\marked.bin")) "previous release quarantined the test file"
$gui = Start-Process "$oldApp\SentinelVision.exe" -ArgumentList '--minimized' -PassThru
# the ransomware shield stores the documents in its vault (wait for it, up to 90 s)
$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Seconds 5
    $oldVault = (& "$oldApp\sentinel-vision-cli.exe" rollback list | Out-String)
} while ($oldVault -notmatch 'Report 1\.txt' -and (Get-Date) -lt $deadline)
Stop-Process -Id $gui.Id -Force -ErrorAction SilentlyContinue
Write-Host $oldVault
Assert ($oldVault -match 'Report 1\.txt') "previous release has documents in its rollback vault"
$gui = Start-Process "$oldApp\SentinelVision.exe" -ArgumentList '--minimized' -PassThru   # running during the upgrade
Start-Sleep -Seconds 10

# ------------------------------------------------------------------------------------------------ 2. upgrade
Progress "upgrade to the new version"
Invoke-Setup $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG="install1.log"') "upgrade from $PreviousVersion"
Assert (Test-Path "$newApp\SentinelVision.exe") "installed in Program Files"
Assert (Test-Path "$newApp\sentinel-vision-service.exe") "service program installed"
Assert ((Test-Path "$newApp\THIRD_PARTY_NOTICES.txt") -and (Select-String -Path "$newApp\THIRD_PARTY_NOTICES.txt" -Pattern 'GNU LESSER GENERAL PUBLIC LICENSE' -Quiet)) "third-party licence notices installed (audit SV-E01)"
Assert (-not (Test-Path "$oldApp\SentinelVision.exe")) "old per-user copy removed"
Assert (-not (Test-Path "HKCU:\$uninstKey")) "old per-user uninstall entry removed"
Assert (Test-Path "HKLM:\$uninstKey") "new uninstall entry registered for all users"
$shown = (Get-ItemProperty "HKLM:\$uninstKey").DisplayName
Assert ($shown -eq 'Sentinel Vision') "listed in Installed apps as plain 'Sentinel Vision' ($shown)"
Assert (-not (Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Sentinel Vision.lnk")) "old Start menu shortcut removed"
Assert (Test-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentinel Vision.lnk") "Start menu shortcut for all users"
$userPath = (Get-ItemProperty 'HKCU:\Environment').Path
Assert (-not ($userPath -like "*$oldApp*")) "old folder removed from the user PATH"
$run = (Get-ItemProperty $runKey -ErrorAction SilentlyContinue).SentinelVision
Assert ($run -eq "`"$newApp\SentinelVision.exe`" --minimized") "start-at-sign-in kept, pointing at Program Files: $run"
$svc = Service-State
Assert ($svc -and $svc.State -eq 'Running') "protection service running"
Assert ($svc.StartName -eq 'LocalSystem' -and $svc.StartMode -eq 'Auto') "service runs as LocalSystem and starts automatically"
$acl = Get-Acl $data
$who = ($acl.Access | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique) -join ', '
Assert ($acl.AreAccessRulesProtected) "protected data folder does not inherit permissions"
Assert (-not ($acl.Access | Where-Object { $_.IdentityReference.Value -notmatch 'SYSTEM|Administrators' })) "only SYSTEM and Administrators can open the protected data ($who)"
$pfAcl = (Get-Acl $newApp).Access | Where-Object { $_.IdentityReference.Value -match 'Users|Everyone|Authenticated' -and $_.FileSystemRights -match 'Write|Modify|FullControl' -and $_.AccessControlType -eq 'Allow' }
Assert (-not $pfAcl) "ordinary users can't modify the program folder"

Progress "data carried over into the protected service"
$status = SvCli @('service')
Assert ($status -match 'Protection service') "the app talks to the service"
Assert ($status -match 'quarantine:\s+[1-9]') "quarantined file moved into protected storage"
$vault = SvCli @('rollback', 'list')
Assert ($vault -match 'Report 1\.txt') "rollback vault moved into protected storage"
Assert (-not (Test-Path (Join-Path $env:LOCALAPPDATA 'SentinelVision\vault\vault.key'))) "old unprotected vault removed"
$appLog = Join-Path $env:LOCALAPPDATA 'SentinelVision\logs\sentinel.log'
Assert (-not (Select-String -Path $appLog -Pattern 'not moved' -Quiet)) "every old document version was accepted by the service"
Assert (-not (Test-Path (Join-Path $env:LOCALAPPDATA 'SentinelVision\quarantine\vault.key'))) "old unprotected quarantine removed"
$v = (SvCli @('rollback', 'versions', "$docs\Report 1.txt"))
$vid = [regex]::Match($v, '(?m)^\s*(\d+)\s').Groups[1].Value
Set-Content -Path "$docs\Report 1.txt" -Value 'overwritten'
SvCli @('rollback', 'restore', $vid) | Out-Null
Assert ((Get-Content "$docs\Report 1.txt" -Raw) -match 'Quarterly report 1') "a document restores from protected storage"

# ------------------------------------------------------------------------------------------------ 3. ordinary account
Progress "an ordinary (non-administrator) account"
$pw = ConvertTo-SecureString ('Sv-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '!a1') -AsPlainText -Force
New-LocalUser -Name 'svtest' -Password $pw -PasswordNeverExpires | Out-Null
$cred = New-Object System.Management.Automation.PSCredential('svtest', $pw)
$results = 'C:\Users\Public\svtest-results.txt'
$probe = @"
`$out = '$results'
# Start-Process -Credential passes on the runner's environment; use this account's own folders
`$env:LOCALAPPDATA = [Environment]::GetFolderPath('LocalApplicationData')
`$env:APPDATA = [Environment]::GetFolderPath('ApplicationData')
`$env:USERPROFILE = [Environment]::GetFolderPath('UserProfile')
`$env:TEMP = Join-Path `$env:LOCALAPPDATA 'Temp'; `$env:TMP = `$env:TEMP
New-Item -ItemType Directory -Force `$env:TEMP | Out-Null
function W([string]`$t) { Add-Content -LiteralPath `$out -Value `$t -Encoding UTF8 }
Set-Content -LiteralPath `$out -Value 'start' -Encoding UTF8
try { Remove-Item '$data' -Recurse -Force -ErrorAction Stop; W 'DELETE_DATA_ALLOWED' } catch { W "delete_data_denied (`$(`$_.Exception.GetType().Name))" }
try { Get-ChildItem '$data' -ErrorAction Stop | Out-Null; W 'LIST_DATA_ALLOWED' } catch { W 'list_data_denied' }
try { [IO.File]::WriteAllText('$newApp\sentinel-vision-cli.exe', 'x'); W 'REPLACE_EXE_ALLOWED' } catch { W 'replace_exe_denied' }
W (& '$newApp\sentinel-vision-cli.exe' service --self-test 2>&1 | Out-String)
W "selftest_exit=`$LASTEXITCODE"
W (& '$newApp\sentinel-vision-cli.exe' rollback list 2>&1 | Out-String)
W "rollback_exit=`$LASTEXITCODE"
# audit SV-A05: an ordinary program can't add a rogue instance of the service's pipe
try { `$ps = New-Object System.IO.Pipes.NamedPipeServerStream('SentinelVisionService', [System.IO.Pipes.PipeDirection]::InOut, -1); W 'PIPE_INSTANCE_ALLOWED'; `$ps.Dispose() } catch { `$e = `$_.Exception; while (`$e.InnerException) { `$e = `$e.InnerException }; W "pipe_instance_denied (`$(`$e.GetType().Name))" }
W 'done'
"@
Set-Content -Path 'C:\Users\Public\svtest.ps1' -Value $probe
$p = Start-Process powershell.exe -Credential $cred -LoadUserProfile -WorkingDirectory 'C:\Users\Public' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\svtest.ps1' -PassThru
$null = $p.Handle
if (-not $p.WaitForExit(300000)) { throw "ordinary-account checks did not finish" }
$r = if (Test-Path $results) { Get-Content $results -Raw -Encoding UTF8 } else { '(no results file: the ordinary-account script did not run)' }
Write-Host $r
Assert ($r -match '(?m)^done') "ordinary-account checks ran to the end: $r"
Assert ($r -match 'delete_data_denied') "an ordinary account can't delete the protected data"
Assert ($r -match 'list_data_denied') "an ordinary account can't even list the protected data"
Assert ($r -match 'replace_exe_denied') "an ordinary account can't replace the program"
Assert ($r -match 'Tamper protection: OK' -and $r -match 'selftest_exit=0') "an ordinary account can't weaken protection through the service: $r"
Assert ($r -match 'Administrator prompts: OK') "the installed program passes the check for running with administrator rights (audit SV-A08): $r"
Assert ($r -match 'pipe_instance_denied \(UnauthorizedAccessException\)') "an ordinary account can't create a rogue pipe instance (audit SV-A05): $r"
Assert ($r -notmatch 'Report 1\.txt' -and $r -match 'rollback_exit=0') "an ordinary account can't see another account's vault: $r"

# audit SV-A01/SV-F04: developer switches are ignored by the installed build (any program could set them)
$env:SENTINEL_VISION_NO_SERVICE = '1'; $env:SENTINEL_VISION_HOME = 'C:\Users\Public\sv-fake-home'
$st = SvCli @('service')
Remove-Item Env:SENTINEL_VISION_NO_SERVICE, Env:SENTINEL_VISION_HOME
Assert ($st -match 'Protection service' -and -not (Test-Path 'C:\Users\Public\sv-fake-home')) "SENTINEL_VISION_NO_SERVICE and SENTINEL_VISION_HOME are ignored by the installed app"

# ------------------------------------------------------------------------------------------------ app + watchdog
Progress "the app with the service"
$gui = Start-Process "$newApp\SentinelVision.exe" -ArgumentList '--minimized' -PassThru
Start-Sleep -Seconds 25
$running = @(Get-Process SentinelVision -ErrorAction SilentlyContinue)
Write-Host "app processes: $($running.Count); started copy exited: $($gui.HasExited)$(if ($gui.HasExited) { " (code $($gui.ExitCode))" })"
# if the watchdog already started the app for this session, the second copy hands over and exits with 0
Assert ($running.Count -ge 1 -and (-not $gui.HasExited -or $gui.ExitCode -eq 0)) "app running after 25 s"
$log = Join-Path $env:LOCALAPPDATA 'SentinelVision\logs\sentinel.log'
if (Test-Path $log) { Assert (-not (Select-String -Path $log -Pattern 'Traceback' -Quiet)) "no Python tracebacks in the app log" }
$mySession = (Get-Process -Id $PID).SessionId
$active = (query user 2>$null | Out-String)
Write-Host "session $mySession; signed-in users:`n$active"
if ($mySession -ne 0 -and $active -match 'Active') {
    $killed = @(Get-Process SentinelVision -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    Stop-Process -Name SentinelVision -Force
    # a new, running app process (an ended one can stay listed while something still holds a handle to it)
    function New-App { Get-Process SentinelVision -ErrorAction SilentlyContinue | Where-Object { $killed -notcontains $_.Id -and -not $_.HasExited } }
    $deadline = (Get-Date).AddSeconds(90)   # the watchdog checks every 15 s
    while (-not (New-App) -and (Get-Date) -lt $deadline) { Start-Sleep 3 }
    $wd = (Get-Content (Join-Path $data 'service.log') | Select-String 'watchdog' | ForEach-Object { $_.Line }) -join '%0A'
    Write-Host "::notice title=Watchdog log::$wd"
    Assert (New-App) "the service restarted the app after it was closed (ended: $($killed -join ', '))"
} else {
    Write-Host "::notice title=Watchdog::not tested here (no interactive desktop session on this machine)"
}

Progress "website and firewall blocking applied by the service"
Progress 'webshield enable'
SvCli @('webshield', 'enable') | Out-Null
Progress 'webshield enabled'
$st = SvCli @('service')
Assert ($st -match 'website blocking: on \([1-9]') "website blocking applied by the service: $st"
$rules = @(Get-NetFirewallRule -DisplayName 'Sentinel Vision - malicious networks *' -ErrorAction SilentlyContinue)
$out1 = $rules | Where-Object { $_.DisplayName -eq 'Sentinel Vision - malicious networks out 1' }
Assert ($out1 -and $out1.Action -eq 'Block' -and $out1.Enabled -eq 'True') "firewall rules for criminal networks created ($($rules.Count) rules; status: $st)"
$addr = @($rules | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress }).Count
Assert ($addr -ge 10) "firewall rules hold the blocked networks ($addr addresses)"

# firewall blocking must never cut off the services the app itself depends on, or big shared hosting
$nets = @(Get-Content (Join-Path $data 'feeds\networks.txt') -ErrorAction SilentlyContinue)
Write-Host "networks blocked: $($nets.Count)"
function In-Net([string]$ip, [string]$cidr) {
    $parts = $cidr.Split('/'); $a = [Net.IPAddress]::Parse($ip); $n = [Net.IPAddress]::Parse($parts[0])
    if ($a.AddressFamily -ne $n.AddressFamily) { return $false }
    $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { $a.GetAddressBytes().Count * 8 }
    $ab = $a.GetAddressBytes(); $nb = $n.GetAddressBytes()
    for ($i = 0; $i -lt $ab.Count; $i++) {
        $m = [Math]::Max(0, [Math]::Min(8, $bits - 8 * $i)); $mask = (0xFF -shl (8 - $m)) -band 0xFF
        if (($ab[$i] -band $mask) -ne ($nb[$i] -band $mask)) { return $false }
    }
    return $true
}
Progress 'checking essential services against the blocked networks'
$hits = @()
$essential = 'github.com', 'api.github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
    'raw.githubusercontent.com', 'www.spamhaus.org', 'feodotracker.abuse.ch', 'rules.emergingthreats.net',
    'urlhaus.abuse.ch', 'threatfox-api.abuse.ch', 'mb-api.abuse.ch', 'hashlookup.circl.lu', 'api.pwnedpasswords.com',
    'phishing.army', 'openphish.com', 'database.clamav.net', 'www.microsoft.com', 'www.google.com', 'www.cloudflare.com'
foreach ($h in $essential) {
    $ips = @(Resolve-DnsName $h -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    foreach ($ip in $ips) { foreach ($c in $nets) { if (In-Net $ip $c) { $hits += "$h $ip in $c" } } }
}
if ($hits) { Write-Host "::warning title=Firewall overlap::$($hits -join '; ')" }
Assert (-not $hits) "no essential service is inside a blocked network ($($hits -join '; '))"
foreach ($u in 'https://api.github.com/', 'https://www.spamhaus.org/drop/drop.txt', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt') {
    try { $null = Invoke-WebRequest $u -UseBasicParsing -Method Head -TimeoutSec 20; $ok = $true } catch { $ok = $_.Exception.Message -notmatch 'forbidden by its access permissions|10013'; Write-Host "$u : $($_.Exception.Message)" }
    Assert $ok "still reachable with firewall blocking on: $u"
}

# ------------------------------------------------------------------------------------------------ companion programs
Progress "tools for companion programs (Agent Guard): quarantine add, plugin log, net block, plugins"
$tool = Join-Path $docs 'agent-tool.exe'
Set-Content -Path $tool -Value 'MZ harmless test file for quarantine add' -NoNewline
$qid = ((SvCli @('quarantine', 'add', $tool, '--reason', 'installer test')) -split "`r?`n" | Where-Object { $_ -match '^[0-9a-f]{32}$' } | Select-Object -Last 1)
Assert ($qid -and -not (Test-Path $tool)) "quarantine add moved the file into protected storage ($qid)"
Assert ((SvCli @('quarantine', 'list')) -match $qid) "the added item is listed"
SvCli @('quarantine', 'restore', $qid) | Out-Null
Assert ((Get-Content $tool -Raw) -eq 'MZ harmless test file for quarantine add') "the added item restores intact"
Remove-Item $tool -Force

SvCli @('plugin-log', 'append', 'agent-guard', '--json', '{"event":"installer-test","n":1}') | Out-Null
SvCli @('plugin-log', 'append', 'agent-guard', '--json', '{"event":"installer-test","n":2}') | Out-Null
$v = SvCli @('plugin-log', 'verify', 'agent-guard')
Assert ($v -match '"intact": true' -and $v -match '"entries": 2' -and $v -match '"protected": true') "plugin log kept by the protection service, chain intact ($v)"
$sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Assert (Test-Path (Join-Path $data "users\$sid\plugins\agent-guard\log.jsonl")) "plugin log stored in the protected folder"

$ip = '45.12.10.9'
SvCli @('net', 'block', $ip) | Out-Null
$blk = @(Get-NetFirewallRule -DisplayName "SentinelVision block $ip" -ErrorAction SilentlyContinue)
Assert ($blk.Count -eq 2 -and ($blk | Where-Object { $_.Action -ne 'Block' }).Count -eq 0) "net block created inbound and outbound block rules"
$blk | Remove-NetFirewallRule
Assert ((SvCli @('net', 'block', '192.168.1.1')) -match 'refusing') "net block refuses private addresses"

$pdir = Join-Path $newApp 'plugins\demo'
New-Item -ItemType Directory -Force (Join-Path $pdir 'sv_demo-1.0.dist-info') | Out-Null
Set-Content -Path (Join-Path $pdir 'sv_demo.py') -Value 'def register(): return []'
Set-Content -Path (Join-Path $pdir 'sv_demo-1.0.dist-info\METADATA') -Value "Metadata-Version: 2.1`nName: sv_demo`nVersion: 1.0"
Set-Content -Path (Join-Path $pdir 'sv_demo-1.0.dist-info\entry_points.txt') -Value "[sentinel_vision.plugins]`nsv_demo = sv_demo:register"
$pl = SvCli @('plugins')
Assert ($pl -match 'sv_demo 1\.0\s+\[waiting for approval\]') "a plugin in the protected Program Files folder is found and waits for approval ($pl)"
icacls $pdir /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null   # let ordinary users change it
$pl = SvCli @('plugins')
Assert ($pl -match 'refused: .*can be changed by S-1-5-32-545') "a plugin folder ordinary users could change is refused ($pl)"
icacls $pdir /remove:g '*S-1-5-32-545' | Out-Null

# ------------------------------------------------------------------------------------------------ 4. upgrades
Progress "upgrade over the running app and service"
Invoke-Setup $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/LOG="install2.log"') "upgrade over itself"
Assert ((Service-State).State -eq 'Running') "service running again after the upgrade"
Assert ((SvCli @('service')) -match 'quarantine:\s+[1-9]') "protected data survived the upgrade"
Assert (Test-Path (Join-Path $pdir 'sv_demo.py')) "plugins added by an administrator survive an upgrade"

Progress "self-update style install relaunches the app"
Invoke-Setup $Setup @('/SILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/RELAUNCH=1', '/LOG="install3.log"') "self-update style install"
Start-Sleep -Seconds 15
Assert (Get-Process SentinelVision -ErrorAction SilentlyContinue) "app relaunched after /RELAUNCH=1"

Progress "unticking start-at-sign-in"
Invoke-Setup $Setup @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS="addtopath"', '/LOG="install4.log"') "install without start-at-sign-in"
Assert ($null -eq (Get-ItemProperty $runKey -Name SentinelVision -ErrorAction SilentlyContinue)) "start-at-sign-in removed"
Assert ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').Path -like "*$newApp*") "command-line tool on the PATH"

# ------------------------------------------------------------------------------------------------ 5. uninstall
Progress "silent uninstall"
$decoy = Join-Path $docs '!Budget 2026.docx'
Invoke-Setup "$newApp\unins000.exe" @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') "uninstaller"
$deadline = (Get-Date).AddSeconds(90)
while ((Test-Path "$newApp\SentinelVision.exe") -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
Assert (-not (Test-Path "$newApp\SentinelVision.exe")) "program files removed"
Assert (-not (Test-Path (Join-Path $newApp 'plugins'))) "plugins folder removed"
Assert ($null -eq (Service-State)) "protection service removed"
Assert ($null -eq (Get-Process SentinelVision, sentinel-vision-service -ErrorAction SilentlyContinue)) "nothing left running"
$left = @(Get-NetFirewallRule -DisplayName 'Sentinel Vision - malicious networks *' -ErrorAction SilentlyContinue)
Assert ($left.Count -eq 0) "firewall rules removed ($($left.Count) left)"
$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw
Assert ($hosts -notmatch 'Sentinel Vision') "website blocking removed from the hosts file"
Assert ($null -eq (Get-ItemProperty $runKey -Name SentinelVision -ErrorAction SilentlyContinue)) "start-at-sign-in removed"
Assert (-not ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').Path -like "*$newApp*")) "PATH entry removed"
Assert (-not (Test-Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentinel Vision.lnk")) "Start menu shortcut removed"
Assert (-not (Test-Path -LiteralPath $decoy)) "ransomware decoys removed"
Assert (Test-Path $data) "protected data kept after a silent uninstall (the user is asked in a normal uninstall)"
Write-Host "Windows installer lifecycle: ALL $script:passed CHECKS PASSED"
Write-Host "::notice title=Windows installer test::$script:passed checks passed: upgrade from $PreviousVersion, Program Files, protection service, tamper protection from an ordinary account, data carried over, blocking, upgrades, uninstall"
