/*
    Sentinel Vision core rules (MIT licensed, written for this project).
    These cover broad, high-signal behaviours. Family-specific coverage comes from
    YARA Forge, downloaded by the updater into the user's data directory.

    meta.severity: low | medium | high | critical
*/

rule SV_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless test string)"
        severity = "critical"
        author = "Sentinel Vision"
    strings:
        $a = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 }
        $b = { 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 21 }
    condition:
        $a at 0 and $b and filesize < 256
}

rule SV_PHP_Webshell_Generic
{
    meta:
        description = "PHP webshell: executes code or commands taken directly from the HTTP request"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $php = "<?php" nocase
        $e1 = /(eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(base64_decode\s*\(\s*)?(gzinflate\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
        $e2 = /preg_replace\s*\(\s*['"].{1,20}\/e['"]\s*,\s*\$_(GET|POST|REQUEST)/ nocase
        $e3 = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $php and any of ($e*)
}

rule SV_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell downloads code from the internet and executes it in memory"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $dl1 = "DownloadString" nocase ascii wide
        $dl2 = "DownloadData" nocase ascii wide
        $dl3 = "Invoke-WebRequest" nocase ascii wide
        $dl4 = "Net.WebClient" nocase ascii wide
        $ex1 = "IEX" ascii wide
        $ex2 = "Invoke-Expression" nocase ascii wide
        $ex3 = "[Reflection.Assembly]::Load" nocase ascii wide
        $hid = /-w(indowstyle)?\s+h(idden)?/ nocase ascii wide
    condition:
        filesize < 5MB and 1 of ($dl*) and 1 of ($ex*) and ($hid or 2 of ($dl*))
}

rule SV_Reverse_Shell_OneLiner
{
    meta:
        description = "Reverse shell one-liner (attacker gets an interactive shell)"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $b1 = /(ba)?sh\s+-i\s*>&\s*\/dev\/tcp\/[0-9a-zA-Z.\-]+\/\d{2,5}/
        $b2 = /exec\s+\d+<>\/dev\/tcp\//
        $n1 = /\b(nc|ncat|netcat)\b[^\n]{0,60}\s-e\s+\/bin\/(ba)?sh/
        $p1 = /socket\.socket\([^\n]{0,200}\.connect\(\([^\n]{0,200}(subprocess\.call|pty\.spawn|os\.dup2)/
        $m1 = "mkfifo /tmp/" ascii
        $m2 = /\|\s*\/bin\/(ba)?sh\s+-i\s+2>&1\s*\|\s*(nc|ncat)/
    condition:
        filesize < 2MB and (any of ($b*) or $n1 or $p1 or ($m1 and $m2))
}

rule SV_Ransomware_Recovery_Inhibition
{
    meta:
        description = "Deletes shadow copies / backups and disables recovery (ransomware behaviour)"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $v1 = "vssadmin delete shadows" nocase ascii wide
        $v2 = "vssadmin.exe delete shadows" nocase ascii wide
        $v3 = "shadowcopy delete" nocase ascii wide
        $w1 = "wbadmin delete catalog" nocase ascii wide
        $b1 = "recoveryenabled no" nocase ascii wide
        $b2 = "bootstatuspolicy ignoreallfailures" nocase ascii wide
        $q = "/quiet" nocase ascii wide
    condition:
        2 of ($v*, $w1, $b*) or (1 of ($v*) and $q)
}

rule SV_Ransom_Note
{
    meta:
        description = "Ransom note text"
        severity = "medium"
        author = "Sentinel Vision"
    strings:
        $a1 = "your files have been encrypted" nocase ascii wide
        $a2 = "all your files are encrypted" nocase ascii wide
        $a3 = "your important files are encrypted" nocase ascii wide
        $p1 = "bitcoin" nocase ascii wide
        $p2 = "monero" nocase ascii wide
        $p3 = ".onion" nocase ascii wide
        $p4 = "decrypt" nocase ascii wide
    condition:
        filesize < 1MB and 1 of ($a*) and 2 of ($p*)
}

rule SV_CoinMiner_Config
{
    meta:
        description = "Cryptocurrency miner configuration or binary"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $s1 = "stratum+tcp://" ascii wide
        $s2 = "stratum+ssl://" ascii wide
        $x1 = "xmrig" nocase ascii wide
        $x2 = "\"donate-level\"" ascii
        $x3 = "randomx" nocase ascii wide
        $x4 = "cryptonight" nocase ascii wide
    condition:
        1 of ($s*) and 1 of ($x*)
}

rule SV_HackTool_Mimikatz
{
    meta:
        description = "Mimikatz credential-dumping tool"
        severity = "critical"
        author = "Sentinel Vision"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase ascii wide
        $s2 = "lsadump::sam" nocase ascii wide
        $s3 = "Invoke-Mimikatz" nocase ascii wide
        $s4 = "gentilkiwi" nocase ascii wide
        $s5 = "mimikatz" nocase ascii wide
        $s6 = "kerberos::golden" nocase ascii wide
    condition:
        2 of them
}

rule SV_AMSI_Bypass
{
    meta:
        description = "Disables the Windows Antimalware Scan Interface"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $a1 = "AmsiUtils" ascii wide
        $a2 = "amsiInitFailed" ascii wide
        $a3 = "AmsiScanBuffer" ascii wide
        $p1 = "VirtualProtect" ascii wide
        $p2 = "GetProcAddress" ascii wide
        $p3 = "SetValue($null,$true)" nocase ascii wide
        $p4 = "NonPublic,Static" nocase ascii wide
    condition:
        filesize < 5MB and 1 of ($a*) and 1 of ($p*)
}

rule SV_Defender_Tampering
{
    meta:
        description = "Disables Microsoft Defender or adds broad exclusions"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $m1 = "Set-MpPreference" nocase ascii wide
        $m2 = "Add-MpPreference" nocase ascii wide
        $o1 = "DisableRealtimeMonitoring" nocase ascii wide
        $o2 = "DisableBehaviorMonitoring" nocase ascii wide
        $o3 = "DisableIOAVProtection" nocase ascii wide
        $o4 = "ExclusionPath" nocase ascii wide
        $r1 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase ascii wide
        $r2 = "DisableAntiSpyware" nocase ascii wide
    condition:
        (1 of ($m*) and 1 of ($o*)) or ($r1 and $r2)
}

rule SV_Office_AutoExec_Shell_Macro
{
    meta:
        description = "Office macro that runs automatically and launches commands"
        severity = "medium"
        author = "Sentinel Vision"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Workbook_Open" nocase
        $auto4 = "Auto_Open" nocase
        $x1 = "WScript.Shell" nocase
        $x2 = "Shell(" nocase
        $x3 = "powershell" nocase
        $x4 = "URLDownloadToFile" nocase
        $x5 = "MSXML2.XMLHTTP" nocase
    condition:
        (uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and 1 of ($auto*) and 2 of ($x*)
}

rule SV_LNK_Script_Launcher
{
    meta:
        description = "Windows shortcut that launches a script host with a download or encoded command"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $h1 = "powershell" nocase ascii wide
        $h2 = "mshta" nocase ascii wide
        $h3 = "cmd.exe" nocase ascii wide
        $h4 = "certutil" nocase ascii wide
        $h5 = "bitsadmin" nocase ascii wide
        $p1 = "http" nocase ascii wide
        $p2 = "-enc" nocase ascii wide
        $p3 = "FromBase64String" nocase ascii wide
    condition:
        uint32(0) == 0x0000004C and filesize < 2MB and 1 of ($h*) and 1 of ($p*)
}

rule SV_Linux_Persistence_Dropper
{
    meta:
        description = "Shell script that downloads a payload into a temp dir, makes it executable and persists"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $d1 = /(curl|wget)\s[^\n]{0,200}(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/)/
        $c1 = /chmod\s+(\+x|[0-7]?7[0-7]{2})\s+[^\n]{0,80}(\/tmp\/|\/dev\/shm\/|\/var\/tmp\/)/
        $p1 = "crontab" ascii
        $p2 = "/etc/rc.local" ascii
        $p3 = ".bashrc" ascii
        $p4 = "systemctl enable" ascii
        $p5 = "authorized_keys" ascii
        $k1 = "pkill" ascii
        $k2 = "kill -9" ascii
    condition:
        filesize < 1MB and $d1 and $c1 and (1 of ($p*) or 1 of ($k*))
}
