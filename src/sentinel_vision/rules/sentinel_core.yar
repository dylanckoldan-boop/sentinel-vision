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
        // IEX applied directly to downloaded content, in either order
        $c1 = /(iex|invoke-expression)\s*\(?\s*\(?\s*(new-object\s+(system\.)?net\.webclient\)?\.download(string|data)|iwr|irm|invoke-webrequest|invoke-restmethod)\b/ nocase ascii wide
        $c2 = /\.download(string|data)\s*\([^)]{1,300}\)\s*\)?\s*\|\s*(iex|invoke-expression)\b/ nocase ascii wide
        $c3 = /\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|\r\n]{1,300}\|\s*(iex|invoke-expression)\b/ nocase ascii wide
    condition:
        uint16(0) != 0x5A4D and filesize < 5MB and any of them
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
        // Strings from two different tools: the Windows tools themselves only ever contain their own commands.
        (1 of ($v*) and $w1) or (1 of ($v*) and 1 of ($b*)) or ($w1 and 1 of ($b*))
        or (uint16(0) != 0x5A4D and filesize < 2MB and 1 of ($v1, $v2) and $q)
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
        description = "Cryptocurrency miner configuration (mining pool plus miner settings)"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        // a real pool endpoint "stratum+tcp://host.tld:port", not just the scheme mentioned in text
        $pool = /stratum\+(tcp|ssl|tls):\/\/[a-zA-Z0-9.-]{3,64}\.[a-zA-Z]{2,10}:[0-9]{2,5}/ ascii wide
        $j_pools = /"pools"\s*:\s*\[/ ascii
        $j_url = /"url"\s*:\s*"stratum\+/ ascii
        $j_donate = /"donate-level"\s*:\s*[0-9]/ ascii
        $j_algo = /"algo"\s*:\s*"(rx|cn|randomx|cryptonight|kawpow|ethash)/ nocase ascii
        $cli_donate = /--donate-level[= ][0-9]/ ascii wide
        $cli_algo = /--algo[= ](rx|cn|randomx|cryptonight|kawpow|ethash)/ nocase ascii wide
    condition:
        filesize < 20MB and $pool and (
            ($j_pools and $j_url and ($j_donate or $j_algo)) or
            ($cli_donate and $cli_algo)
        )
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
        description = "Script that disables the Windows Antimalware Scan Interface"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $a1 = "AmsiUtils" nocase ascii wide
        $a2 = "amsiInitFailed" nocase ascii wide
        $a3 = "AmsiScanBuffer" ascii wide
        $p1 = "VirtualProtect" ascii wide
        $p2 = "GetProcAddress" ascii wide
        $p3 = /SetValue\(\s*\$null\s*,\s*\$true\s*\)/ nocase ascii wide
    condition:
        // scripts only: amsi.dll and legitimate security products contain these API names
        uint16(0) != 0x5A4D and filesize < 2MB and (($a1 and ($a2 or $p3)) or ($a3 and $p1 and $p2))
}

rule SV_Defender_Tampering
{
    meta:
        description = "Script that disables Microsoft Defender or adds broad exclusions"
        severity = "high"
        author = "Sentinel Vision"
    strings:
        $m1 = /Set-MpPreference\s+(-\w+\s+\S+\s+)*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|BlockAtFirstSeen)\s+(\$true|1)\b/ nocase ascii wide
        $m2 = /Add-MpPreference\s+(-\w+\s+\S+\s+)*-Exclusion(Path|Process|Extension)\s+["']?([a-z]:\\?["']?(\s|$)|\*|\.?exe\b)/ nocase ascii wide
        $r1 = /Windows Defender[^\r\n]{0,80}\/v\s+"?DisableAntiSpyware"?[^\r\n]{0,60}\/d\s+1/ nocase ascii wide
    condition:
        // scripts only: Defender's own PowerShell module and binaries contain these names legitimately
        uint16(0) != 0x5A4D and filesize < 5MB and any of them
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
