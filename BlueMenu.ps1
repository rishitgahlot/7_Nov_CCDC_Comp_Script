<#
.SYNOPSIS
  BlueMenu.ps1 - one script for every blue team box. pfSense-style numbered menu; shows only what applies
  to the machine it runs on (transporters = smb, stewards = iis, teamradio = winrm).

.DESCRIPTION
  Copy this single file to every machine and run it from an ELEVATED PowerShell:
      powershell -ExecutionPolicy Bypass -File .\BlueMenu.ps1
  Role comes from the hostname; override with  -Role smb|iis|winrm|generic  or menu option R.
  -Watchdog  : skip the menu and run the service watchdog loop (menu option opens this in a new window).

  Safety model
   * Everything this script changes is written to a journal (C:\BlueOps\journal.jsonl) and can be undone from the menu.
   * Config snapshots (menu: Snapshots) can restore services, tasks, autoruns, firewall, users, shares, IIS and WinRM settings.
   * It never touches whiteteam/blackteam, Datadog, the management net, or the NetBird egress (packet rules 6 and 14).
   * It never changes how a scored service answers a check (rule 10); anything risky is opt-in and says how to revert.
   * Run it only during hands-on periods (rule 7). Publish it in a public repo and give organizers the link (rules 20/24).
  Written for Windows PowerShell 5.1. UNTESTED on real hosts when written: try it in your own VM first (rule 18).
#>
[CmdletBinding()]
param(
    [ValidateSet('smb', 'iis', 'winrm', 'generic')][string]$Role,
    [switch]$Watchdog,
    [int]$IntervalSec = 15
)
$ErrorActionPreference = 'Continue'

# ============================================================================================
#  CORE: paths, logging, prompts, journal, classification
# ============================================================================================
$script:Root = 'C:\BlueOps'
foreach ($d in $script:Root, "$script:Root\snap", "$script:Root\quarantine", "$script:Root\evidence", "$script:Root\evtx") {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
$script:LogFile      = Join-Path $script:Root 'blue.log'
$script:Journal      = Join-Path $script:Root 'journal.jsonl'
$script:JournalUndone = Join-Path $script:Root 'journal-undone.txt'
$script:Vault        = Join-Path $script:Root 'vault.csv'
$script:NoRotateFile = Join-Path $script:Root 'no-rotate.txt'
$script:RegBase      = Join-Path $script:Root 'regwatch-baseline.json'
$script:SvcBase      = Join-Path $script:Root 'svc-baseline.csv'
$script:ProtectedUsers = @('whiteteam', 'blackteam')

function Log {
    param([string]$Msg, [string]$Lvl = 'INFO')
    $l = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Lvl, $Msg
    Add-Content -Path $script:LogFile -Value $l
    $c = @{ INFO = 'Gray'; WARN = 'Yellow'; ALERT = 'Red'; OK = 'Green'; ACTION = 'Cyan' }[$Lvl]
    if (-not $c) { $c = 'Gray' }
    Write-Host $l -ForegroundColor $c
}
function Show-Text { param($Obj) ($Obj | Out-String).TrimEnd() | Write-Host }
function Ask { param([string]$Prompt, [string]$Def = '') $r = Read-Host $Prompt; if ([string]::IsNullOrWhiteSpace($r)) { return $Def }; return $r.Trim() }
function Confirm-Yes { param([string]$Prompt) return ((Read-Host "$Prompt  (type YES to proceed)") -ceq 'YES') }
function Confirm-YN { param([string]$Prompt, [bool]$Default = $false)
    $d = if ($Default) { 'Y/n' } else { 'y/N' }
    $r = Read-Host "$Prompt [$d]"
    if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
    return ($r.Trim().ToLower() -in 'y', 'yes')
}
function Pause-Menu { [void](Read-Host 'Press Enter to return to the menu') }
function Select-Indexes {
    param([string]$Prompt, [int]$Max)
    $r = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($r)) { return @() }
    if ($r.Trim().ToLower() -eq 'all') { return @(1..$Max) }
    $out = @()
    foreach ($t in ($r -split '[,\s]+')) {
        if ($t -match '^(\d+)-(\d+)$') { $out += [int]$Matches[1]..[int]$Matches[2] }
        elseif ($t -match '^\d+$') { $out += [int]$t }
    }
    return @($out | Where-Object { $_ -ge 1 -and $_ -le $Max } | Sort-Object -Unique)
}
function Assert-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated (Administrator) PowerShell.' }
}
function Test-Protected { param([string]$Name) return ($script:ProtectedUsers -contains (($Name -split '\\')[-1].ToLower())) }

# Is this process owned by whiteteam/blackteam, or part of Datadog? (rules 6 and 14: out of scope)
function Test-ProcProtected {
    param([int]$ProcId)
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction Stop
        $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
        if ($o.User -and (Test-Protected $o.User)) { return $true }
        if (Test-DatadogName ("{0} {1} {2}" -f $p.Name, $p.ExecutablePath, $o.User)) { return $true }
    } catch { }
    return $false
}
# Rule 10: changing how a scored service is configured needs White/Black Team permission.
function Confirm-Rule10 {
    param([string]$What)
    Write-Host ("RULE 10: {0} changes how a scored service is configured. Do it only with White/Black Team permission." -f $What) -ForegroundColor Yellow
    return (Confirm-Yes 'Do you have that permission?')
}
function Test-DatadogName { param([string]$Text) return ($Text -match '(?i)datadog|dd-agent|ddagentuser') }

function Get-BlueRole {
    switch -Wildcard ($env:COMPUTERNAME.ToLower()) {
        'transporters*' { return 'smb' }
        'stewards*'     { return 'iis' }
        'teamradio*'    { return 'winrm' }
        default         { return 'generic' }
    }
}
function Get-TeamNumber {
    foreach ($ip in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress) {
        if ($ip -match '^10\.(\d+)\.1\.') { return [int]$Matches[1] }
        if ($ip -match '^192\.168\.(\d+)\.') { return [int]$Matches[1] }
    }
    return $null
}

# ---- role configuration ----
$script:RoleCfg = @{
    smb     = @{ Services = @('LanmanServer'); Ports = @(445);  Expected = @(135, 139, 445, 3389, 5985, 5986, 47001);
                 Rules = @('FPS-SMB-In-TCP') }
    iis     = @{ Services = @('W3SVC', 'WAS'); Ports = @(80);   Expected = @(80, 443, 135, 139, 445, 3389, 5985, 5986, 47001);
                 Rules = @('IIS-WebServerRole-HTTP-In-TCP', 'IIS-WebServerRole-HTTPS-In-TCP') }
    winrm   = @{ Services = @('WinRM');        Ports = @(5985); Expected = @(5985, 5986, 135, 139, 445, 3389, 47001);
                 Rules = @('WINRM-HTTP-In-TCP', 'WINRM-HTTP-In-TCP-PUBLIC') }
    generic = @{ Services = @();               Ports = @();     Expected = @(135, 139, 445, 3389, 5985, 5986, 47001); Rules = @() }
}
# Windows foundation services that should always be running (Red likes to disable these).
$script:CoreServices = @('EventLog', 'RpcSs', 'RpcEptMapper', 'DcomLaunch', 'BFE', 'mpssvc', 'Winmgmt', 'CryptSvc', 'Schedule', 'Dnscache', 'LanmanWorkstation')
# Remote-access services. You reach the cloud boxes from the LAN boxes, so never disable these without a plan.
$script:AccessServices = @('TermService', 'WinRM')
# Never disable/stop these from the attack-surface tools.
$script:NeverService = @('RpcSs', 'RpcEptMapper', 'DcomLaunch', 'EventLog', 'Dhcp', 'Dnscache', 'BFE', 'mpssvc', 'CryptSvc', 'gpsvc', 'Winmgmt',
    'LSM', 'SamSs', 'Schedule', 'Netlogon', 'LanmanWorkstation', 'LanmanServer', 'netprofm', 'NlaSvc', 'W3SVC', 'WAS', 'WinRM', 'TermService',
    'UmRdpService', 'SessionEnv', 'KeyIso', 'ProfSvc', 'UserManager', 'nsi', 'Power', 'PlugPlay', 'TrustedInstaller', 'WinDefend', 'wscsvc',
    'sppsvc', 'TimeBrokerSvc', 'StateRepository', 'W32Time')
# Common attack-surface services that are safe to disable on these boxes (none are scored here).
$script:RiskyServices = @('Spooler', 'RemoteRegistry', 'SSDPSRV', 'upnphost', 'lltdsvc', 'TlntSvr', 'SNMP', 'FDResPub', 'fdPHost',
    'WMPNetworkSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc', 'bthserv', 'icssvc', 'WerSvc', 'MapsBroker', 'lfsvc', 'SharedAccess')
$script:SusPath = '(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop|Documents)\\|\\Windows\\Temp\\|\\ProgramData\\|\\Users\\Public\\|\\\$Recycle\.Bin\\'
$script:OkPath  = '(?i)\\ProgramData\\Microsoft\\Windows Defender\\|\\ProgramData\\Microsoft\\Windows\\|\\AppData\\Local\\Microsoft\\(OneDrive|Teams|WindowsApps|Edge)'
$script:BadCmd  = '(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|FromBase64String|DownloadString|DownloadFile|IEX\s*\(|Invoke-Expression|-w(indowstyle)?\s+hidden|certutil.*-urlcache|bitsadmin.*/transfer|mshta|regsvr32.*/i:|rundll32.*javascript|ncat|socat'

# ---- registry helpers ----
function Get-RegRaw {
    param([string]$Path, [string]$Name)
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($k.GetValueNames() -contains $Name) {
            $v = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            if ($v -is [array]) { return ($v -join '|') }
            return "$v"
        }
    } catch { }
    return $null
}
function Get-SvcStart {
    param([string]$Name)
    $v = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" 'Start'
    if ($null -eq $v) { return $null }
    return [int]$v
}
function Get-SvcDeps {
    param([string]$Name)
    try {
        $d = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name DependOnService -ErrorAction Stop).DependOnService
        return @($d | Where-Object { $_ } | ForEach-Object { $_.TrimStart('+') })
    } catch { return @() }
}

# ---- signatures / classification ----
$script:SigCache = @{}
function Get-SigInfo {
    param([string]$Path)
    if (-not $Path) { return 'missing' }
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return 'missing' }
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
    $r = 'unsigned'
    if ($s -and $s.Status -eq 'Valid') { $r = if ($s.SignerCertificate.Subject -match 'Microsoft') { 'microsoft' } else { 'signed-3rd' } }
    $script:SigCache[$Path] = $r
    return $r
}
function Get-ExePath {
    param([string]$Cmd)
    if (-not $Cmd) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim())
    $c = $c -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:windir
    if ($c -match '^system32\\') { $c = Join-Path $env:windir $c }
    $p = $null
    if ($c -match '^"([^"]+)"') { $p = $Matches[1] }
    elseif ($c -match '^([A-Za-z]:\\.*?\.(exe|bat|cmd|ps1|vbs|js|dll|com|scr|sys))') { $p = $Matches[1] }
    else { $p = ($c -split ' ')[0] }
    if ($p -and -not [IO.Path]::IsPathRooted($p)) {
        $g = Get-Command $p -ErrorAction SilentlyContinue
        if ($g) { $p = $g.Source }
    }
    return $p
}
function Get-ItemClass {
    param([string]$Cmd, [string]$Name)
    if (Test-DatadogName "$Cmd $Name") { return 'protected' }
    $p = Get-ExePath $Cmd
    if ($Cmd -match '(?i)\b(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)(\.exe)?\b' -or $Cmd -match $script:BadCmd) { return 'SUSPECT' }
    $sig = Get-SigInfo $p
    if ($sig -eq 'microsoft') { return 'microsoft' }
    if (($p -match $script:SusPath -and $p -notmatch $script:OkPath) -or $sig -in 'unsigned', 'missing') { return 'SUSPECT' }
    return 'review'
}

# ---- IP helpers ----
function ConvertTo-IpNumber { param([string]$Ip) $b = [Net.IPAddress]::Parse($Ip).GetAddressBytes(); [Array]::Reverse($b); return [uint64][BitConverter]::ToUInt32($b, 0) }
function Test-IpInCidr {
    param([string]$Ip, [string]$Cidr)
    $p = $Cidr.Split('/'); $len = [int]$p[1]
    if ($len -eq 0) { return $true }
    $mask = [uint64]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $len))
    return (((ConvertTo-IpNumber $Ip) -band $mask) -eq ((ConvertTo-IpNumber $p[0]) -band $mask))
}

# ============================================================================================
#  JOURNAL: every change made by this script is recorded and can be undone
# ============================================================================================
function Add-Journal {
    param([string]$Type, [hashtable]$Data)
    $id = 1
    if (Test-Path $script:Journal) { $id = @(Get-Content $script:Journal).Count + 1 }
    $o = @{ id = $id; time = (Get-Date -Format s); type = $Type; data = $Data }
    ($o | ConvertTo-Json -Compress -Depth 6) | Add-Content -Path $script:Journal -Encoding UTF8
    return $id
}
function Get-JournalEntries {
    $undone = @(); if (Test-Path $script:JournalUndone) { $undone = @(Get-Content $script:JournalUndone) }
    if (-not (Test-Path $script:Journal)) { return @() }
    $out = @()
    foreach ($l in Get-Content $script:Journal) {
        if (-not $l.Trim()) { continue }
        $e = $l | ConvertFrom-Json
        $e | Add-Member -NotePropertyName undone -NotePropertyValue ($undone -contains "$($e.id)") -Force
        $out += $e
    }
    return $out
}
function Get-ScModeWord { param([int]$Start) switch ($Start) { 0 { 'boot' } 1 { 'system' } 2 { 'auto' } 3 { 'demand' } 4 { 'disabled' } default { 'demand' } } }

function Format-JournalEntry {
    param($E)
    $d = $E.data
    switch ($E.type) {
        'scstart'   { return "service $($d.name): start type was $(Get-ScModeWord $d.oldStart), state was $($d.oldState)" }
        'sddl'      { return "service $($d.name): permissions (SDDL) replaced" }
        'task'      { return "scheduled task $($d.path)$($d.name) disabled" }
        'runkey'    { return "autorun $($d.key)\$($d.name) removed (was: $($d.value))" }
        'startfile' { return "startup file moved: $($d.orig)" }
        'fwrule'    { return "firewall rule disabled: $($d.name)" }
        'fwblock'   { return "firewall block rule created: $($d.name)" }
        'regset'    { return "registry $($d.path)\$($d.name) changed (old: $(if ($d.existed) { $d.value } else { '<absent>' }))" }
        'user'      { return "local account $($d.name) disabled" }
        default     { return "$($E.type)" }
    }
}

function Undo-JournalEntry {
    param($E)
    $d = $E.data
    try {
        switch ($E.type) {
            'scstart' {
                sc.exe config $d.name start= (Get-ScModeWord ([int]$d.oldStart)) | Out-Null
                if ($d.oldState -eq 'Running') { Start-Service -Name $d.name -ErrorAction SilentlyContinue }
            }
            'sddl'      { sc.exe sdset $d.name $d.old | Out-Null }
            'task'      { Enable-ScheduledTask -TaskPath $d.path -TaskName $d.name -ErrorAction Stop | Out-Null }
            'runkey'    { New-ItemProperty -Path $d.key -Name $d.name -Value $d.value -PropertyType $d.kind -Force | Out-Null }
            'startfile' { Move-Item -LiteralPath $d.quarantine -Destination $d.orig -Force -ErrorAction Stop }
            'fwrule'    { Set-NetFirewallRule -Name $d.name -Enabled True }
            'fwblock'   { Remove-NetFirewallRule -Name $d.name -ErrorAction Stop }
            'regset'    {
                if ($d.existed) { New-ItemProperty -Path $d.path -Name $d.name -Value $d.value -PropertyType $d.kind -Force | Out-Null }
                else { Remove-ItemProperty -Path $d.path -Name $d.name -ErrorAction SilentlyContinue }
            }
            'user'      { Enable-LocalUser -Name $d.name }
            default     { Log "Entry $($E.id) of type $($E.type) has no automatic undo." 'WARN'; return $false }
        }
        Add-Content -Path $script:JournalUndone -Value "$($E.id)"
        Log ("Undid #{0}: {1}" -f $E.id, (Format-JournalEntry $E)) 'ACTION'
        return $true
    } catch { Log ("Could not undo #{0}: {1}" -f $E.id, $_) 'ALERT'; return $false }
}

# Registry change with journal (old value remembered). Kind: String|ExpandString|DWord|QWord
function Set-RegJournal {
    param([string]$Path, [string]$Name, $Value, [string]$Kind = 'DWord')
    $existed = $false; $old = $null; $oldKind = $Kind
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($k.GetValueNames() -contains $Name) {
            $existed = $true
            $old = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
            $oldKind = "$($k.GetValueKind($Name))"
        }
    } catch { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
    [void](Add-Journal 'regset' @{ path = $Path; name = $Name; existed = $existed; value = $old; kind = $oldKind })
}
function Remove-RegJournal {
    param([string]$Path, [string]$Name)
    $k = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $k -or ($k.GetValueNames() -notcontains $Name)) { return }
    $old = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'); $kind = "$($k.GetValueKind($Name))"
    Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    [void](Add-Journal 'regset' @{ path = $Path; name = $Name; existed = $true; value = $old; kind = $kind })
}

# Run a command as SYSTEM through a throwaway scheduled task (used only to repair service permissions).
function Invoke-AsSystem {
    param([string]$Command)
    $tn = 'BlueTmp' + (Get-Random)
    schtasks /create /tn $tn /tr "cmd /c $Command" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f 2>&1 | Out-Null
    schtasks /run /tn $tn 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    schtasks /delete /tn $tn /f 2>&1 | Out-Null
}

# ============================================================================================
#  ACCOUNTS: audit, rotate (with vault), show password, test login, open shell as user
#  Rule check (packet rule 6): only whiteteam / blackteam are out of scope. They are never listed as targets.
#  Domain accounts (principal, sportingdir, chiefeng, strategist, pitcrew...) live on pitwall (AD). They are handled by the
#  separate DOMAIN options (A / D / E in the Accounts menu) and only work on a domain-joined machine with reset rights.
#  The packet does NOT say which account Hermes uses for scored checks. Ask White Team or check the Hermes
#  debug page, then add that account to the "never rotate" list (menu: Accounts > N).
# ============================================================================================
$script:ExpectedLocal  = @('scrutineer', 'techdirector', 'crewchief', 'firecrew', 'jackcrew', 'garagecrew', 'celebrity', 'pitlaner', 'reserve', 'gunners')
$script:ExpectedAdmins = @('scrutineer', 'techdirector', 'crewchief', 'firecrew')
$script:DefaultAccts   = @('administrator', 'guest', 'defaultaccount', 'wdagutilityaccount', 'whiteteam', 'blackteam')

function Get-AdminNames {
    $out = net localgroup Administrators 2>$null
    $started = $false; $r = @()
    foreach ($l in $out) {
        if ($l -match '^-{5,}') { $started = $true; continue }
        if ($l -match 'command completed') { break }
        if ($started -and $l.Trim()) { $r += $l.Trim() }
    }
    return $r
}
function New-Pw {
    param([int]$Len = 16)
    $u = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $l = 'abcdefghijkmnpqrstuvwxyz'; $d = '23456789'; $all = $u + $l + $d
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    do {
        $chars = @()
        for ($i = 0; $i -lt $Len; $i++) {
            $b = New-Object byte[] 4; $rng.GetBytes($b)
            $chars += $all[[int]([BitConverter]::ToUInt32($b, 0) % $all.Length)]
        }
        $pw = -join $chars
    } until (($pw -cmatch '[A-Z]') -and ($pw -cmatch '[a-z]') -and ($pw -match '\d'))
    return $pw
}

# ---- vault: C:\BlueOps\vault.enc  (AES-256 + HMAC, key from a passphrase you type; the passphrase is never written to disk) ----
# Password text is handled with .NET calls and plain loops only: PowerShell module logging (event 4103) records the
# arguments and pipeline input of cmdlets, so passwords must never be passed to a cmdlet (Write-Host, Format-Table,
# ConvertTo-SecureString, Where-Object...). Screens that show passwords use [Console]::WriteLine, which transcripts skip.
$script:VaultFile = Join-Path $script:Root 'vault.enc'
$script:VKeyEnc = $null; $script:VKeyMac = $null
$script:VSep = [string][char]31

function ConvertTo-Secure {
    param([string]$Pw)
    $s = New-Object System.Security.SecureString
    foreach ($c in $Pw.ToCharArray()) { $s.AppendChar($c) }
    $s.MakeReadOnly()
    return $s
}
function Read-Passphrase {
    param([string]$Prompt)
    $ss = Read-Host $Prompt -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}
function Set-VaultKey {
    param([string]$Pass, [byte[]]$Salt)
    $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($Pass, $Salt, 100000)
    $k = $kdf.GetBytes(64)
    $script:VKeyEnc = [byte[]]($k[0..31])
    $script:VKeyMac = [byte[]]($k[32..63])
}
function Protect-VaultText {
    param([string]$Text)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $script:VKeyEnc; $aes.GenerateIV()
    $pt = [Text.Encoding]::UTF8.GetBytes($Text)
    $ct = $aes.CreateEncryptor().TransformFinalBlock($pt, 0, $pt.Length)
    $body = [byte[]]($aes.IV + $ct)
    $mac = [Security.Cryptography.HMACSHA256]::new($script:VKeyMac).ComputeHash($body)
    return [Convert]::ToBase64String([byte[]]($body + $mac))
}
function Unprotect-VaultText {
    param([string]$B64)
    $all = [Convert]::FromBase64String($B64)
    if ($all.Length -lt 65) { throw 'bad record' }
    $body = [byte[]]($all[0..($all.Length - 33)])
    $mac = [byte[]]($all[($all.Length - 32)..($all.Length - 1)])
    $calc = [Security.Cryptography.HMACSHA256]::new($script:VKeyMac).ComputeHash($body)
    $diff = 0; for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($calc[$i] -bxor $mac[$i]) }
    if ($diff -ne 0) { throw 'MAC mismatch' }
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $script:VKeyEnc; $aes.IV = [byte[]]($body[0..15])
    $ct = [byte[]]($body[16..($body.Length - 1)])
    return [Text.Encoding]::UTF8.GetString($aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length))
}
function Add-VaultRaw {
    param([string]$User, [string]$Pw, [string]$Note)
    $rec = (Get-Date -Format 's') + $script:VSep + $User + $script:VSep + $Pw + $script:VSep + $Note
    [IO.File]::AppendAllText($script:VaultFile, (Protect-VaultText $rec) + "`r`n")
}
# Ask for the passphrase (once per run). Creates the vault the first time. Returns $false if it cannot be unlocked.
function Unlock-Vault {
    if ($script:VKeyEnc) { return $true }
    if (Test-Path $script:VaultFile) {
        $lines = [IO.File]::ReadAllLines($script:VaultFile)
        $salt = [Convert]::FromBase64String($lines[0].Substring(11))
        for ($try = 0; $try -lt 3; $try++) {
            $p = Read-Passphrase 'Vault passphrase'
            Set-VaultKey $p $salt
            if ($lines.Count -lt 2) { return $true }
            try { [void](Unprotect-VaultText $lines[1]); return $true }
            catch { Write-Host 'Wrong passphrase.' -ForegroundColor Red; $script:VKeyEnc = $null; $script:VKeyMac = $null }
        }
        return $false
    }
    Write-Host 'No vault yet. Choose a passphrase to lock it. It is NOT saved anywhere: if you forget it the vault cannot be read.' -ForegroundColor Cyan
    $p1 = Read-Passphrase 'New vault passphrase (8+ characters)'
    $p2 = Read-Passphrase 'Repeat it'
    if ($p1.Length -lt 8 -or $p1 -cne $p2) { Write-Host 'Passphrases differ or are too short. Nothing was created.' -ForegroundColor Red; return $false }
    $salt = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    Set-VaultKey $p1 $salt
    [IO.File]::WriteAllText($script:VaultFile, ('BLUEVAULT1:' + [Convert]::ToBase64String($salt) + "`r`n"))
    icacls $script:VaultFile /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
    Add-VaultRaw '#check' 'x' 'passphrase check'
    if (Test-Path $script:Vault) {                                   # one-time import of an old plaintext vault.csv
        foreach ($r in @(Import-Csv $script:Vault)) { Add-VaultRaw $r.user $r.password $r.note }
        $len = (Get-Item $script:Vault).Length
        [IO.File]::WriteAllBytes($script:Vault, (New-Object byte[] $len)); Remove-Item $script:Vault -Force
        Log 'Old plaintext vault.csv imported into the encrypted vault and wiped.' 'ACTION'
    }
    Log 'Encrypted vault created.' 'ACTION'
    return $true
}
function Add-Vault {
    param([string]$User, [string]$Pw, [string]$Note)
    if (-not (Unlock-Vault)) { throw 'Vault is locked (wrong or missing passphrase)' }
    Add-VaultRaw $User $Pw $Note
}
function Get-VaultRows {
    $rows = New-Object System.Collections.ArrayList
    if (-not (Test-Path $script:VaultFile)) { return $rows.ToArray() }
    if (-not (Unlock-Vault)) { return $rows.ToArray() }
    $lines = [IO.File]::ReadAllLines($script:VaultFile)
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if (-not $lines[$i].Trim()) { continue }
        try { $t = Unprotect-VaultText $lines[$i] } catch { continue }
        $f = $t.Split([char]31)
        if ($f[1] -eq '#check') { continue }
        [void]$rows.Add([pscustomobject]@{ time = $f[0]; user = $f[1]; password = $f[2]; note = $f[3] })
    }
    return $rows.ToArray()
}
function Get-VaultLatest { $h = @{}; foreach ($r in (Get-VaultRows)) { $h[$r.user] = $r }; return $h }
function Copy-SecretToClipboard {
    param([string]$Text)
    try { Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::SetText($Text); return $true }
    catch { try { $Text | & clip.exe; return $true } catch { return $false } }
}
function Clear-SecretClipboard { try { Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::Clear() } catch { } }

# ---- Assume-compromised mode: by default new passwords are NOT stored on the machine. They are shown once; you record them off-box. ----
$script:StoreVault = $false
$script:Fresh = New-Object System.Collections.ArrayList
function Save-NewPw {
    param([string]$User, [string]$Pw, [string]$Note)
    [void]$script:Fresh.Add([pscustomobject]@{ user = $User; password = $Pw })
    if ($script:StoreVault) { Add-Vault $User $Pw $Note }
}
function Show-FreshPasswords {
    if ($script:Fresh.Count -eq 0) { return }
    while ($true) {
        [Console]::WriteLine('')
        [Console]::WriteLine('NEW PASSWORDS: record them OFF this machine now (paper or your own laptop). They are not stored here.')
        foreach ($f in $script:Fresh) { [Console]::WriteLine(('  {0,-32} {1}' -f $f.user, $f.password)) }
        [Console]::WriteLine('')
        if ((Read-Host 'Type SAVED once you have recorded them (Enter shows them again)') -ceq 'SAVED') { break }
    }
    $script:Fresh = New-Object System.Collections.ArrayList
    Clear-Host
    Write-Host 'Passwords cleared from this session. Verify with Hermes / a test login.' -ForegroundColor Cyan
}
function Toggle-StoreVault {
    if ($script:StoreVault) { $script:StoreVault = $false; Log 'Storing passwords on this machine: OFF.' 'ACTION'; return }
    Write-Host 'If Red already controls this machine, a stored vault can be stolen (the passphrase can be captured as you type it).' -ForegroundColor Yellow
    if (Confirm-Yes 'Turn ON encrypted storage on this machine anyway?') { $script:StoreVault = $true; Log 'Storing passwords on this machine: ON (encrypted vault).' 'WARN' }
}

function Get-NoRotate { if (Test-Path $script:NoRotateFile) { return @(Get-Content $script:NoRotateFile | Where-Object { $_.Trim() }) } return @() }
function Set-NoRotate {
    Write-Host ('Currently never rotated: ' + ((Get-NoRotate) -join ', '))
    Write-Host 'List accounts that scored services (Hermes) or teammates depend on. Rotating them can fail uptime checks.'
    $n = Ask 'Comma-separated account names (blank keeps current list)'
    if ($n) { ($n -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Set-Content $script:NoRotateFile; Log 'Never-rotate list updated.' 'ACTION' }
    elseif (-not (Test-Path $script:NoRotateFile)) { '' | Set-Content $script:NoRotateFile }
}
function Test-LocalCredential {
    param([string]$User, [string]$Pw)
    if ($User -match '\\') {
        $parts = $User -split '\\', 2
        if ($parts[0] -ine $env:COMPUTERNAME) { return (Test-DomainCredential $parts[1] $Pw) }
        $User = $parts[1]
    }
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $env:COMPUTERNAME)
        return $ctx.ValidateCredentials($User, $Pw)
    } catch { return $false }
}
function Get-AccountDependents {
    param([string]$User)
    $rx = '(^|\\)' + [regex]::Escape($User) + '(@.*)?$'
    $svc = @(Get-CimInstance Win32_Service | Where-Object { $_.StartName -match $rx } | ForEach-Object { "service:$($_.Name)" })
    $tsk = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.Principal.UserId -match $rx } | ForEach-Object { "task:$($_.TaskName)" })
    return @($svc + $tsk)
}

function Show-AccountAudit {
    $admins = Get-AdminNames
    Log ('Local Administrators group: ' + ($admins -join ', '))
    $rows = Get-LocalUser | ForEach-Object {
        $n = $_.Name.ToLower()
        $isAdmin = [bool]($admins | Where-Object { ($_ -split '\\')[-1].ToLower() -eq $n })
        $st = 'ok'
        if ($script:DefaultAccts -contains $n) { $st = 'default/out-of-scope' }
        elseif ($script:ExpectedLocal -notcontains $n) { $st = 'UNEXPECTED ACCOUNT' }
        if ($isAdmin -and ($script:ExpectedAdmins -notcontains $n) -and ($n -notin 'administrator', 'whiteteam', 'blackteam')) { $st = 'UNEXPECTED ADMIN' }
        [pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; Admin = $isAdmin; PwdLastSet = $_.PasswordLastSet; LastLogon = $_.LastLogon; Status = $st }
    }
    Show-Text ($rows | Sort-Object Name | Format-Table -AutoSize)
    foreach ($r in @($rows | Where-Object { $_.Status -like 'UNEXPECTED*' })) { Log ("{0}: {1} (enabled={2})" -f $r.Status, $r.Name, $r.Enabled) 'ALERT' }
    foreach ($a in $admins) {
        $s = ($a -split '\\')[-1].ToLower()
        if (($script:ExpectedAdmins -notcontains $s) -and ($s -notin 'administrator', 'whiteteam', 'blackteam') -and ($a -notmatch 'Domain Admins')) { Log "Admin group member not in packet list: $a" 'ALERT' }
    }
}

function Invoke-Rotate {
    param([string[]]$Only)
    if (-not (Test-Path $script:NoRotateFile)) { Write-Host 'First, tell me which accounts must NOT be rotated.'; Set-NoRotate }
    $no = Get-NoRotate
    $cands = @(Get-LocalUser | Where-Object { $_.Enabled })
    if ($Only) { $cands = @($cands | Where-Object { $Only -contains $_.Name }) }
    $plan = @()
    foreach ($u in $cands) {
        $n = $u.Name.ToLower()
        if (Test-Protected $u.Name) { continue }                                  # rule 6
        if ($n -in 'guest', 'defaultaccount', 'wdagutilityaccount') { continue }
        if ($no | Where-Object { $_.ToLower() -eq $n }) { Log "Skipping $($u.Name): on the never-rotate list" 'INFO'; continue }
        $dep = Get-AccountDependents $u.Name
        $plan += [pscustomobject]@{ User = $u.Name; Current = ($u.Name -ieq $env:USERNAME); Dependents = ($dep -join ' ') }
    }
    if (-not $plan) { Log 'Nothing eligible to rotate.' 'WARN'; return }
    if ($script:StoreVault -and -not (Unlock-Vault)) { Log 'Vault could not be unlocked: nothing was changed.' 'ALERT'; return }
    Write-Host 'Accounts that will get a NEW random password:'
    Show-Text ($plan | Format-Table -AutoSize)
    if ($plan | Where-Object { $_.Dependents }) { Write-Host 'Accounts with Dependents run a service/task: changing their password stops those until you update them.' -ForegroundColor Yellow }
    if (-not (Confirm-Yes 'Rotate these accounts now?')) { return }
    foreach ($p in $plan) {
        if ($p.Dependents) {
            if (-not (Confirm-YN "  $($p.User) is used by [$($p.Dependents)]. Rotate anyway?" $false)) { Log "Skipped $($p.User)" 'INFO'; continue }
        }
        $pw = New-Pw
        try {
            Set-LocalUser -Name $p.User -Password (ConvertTo-Secure $pw) -ErrorAction Stop
            Save-NewPw $p.User $pw 'rotated'
            $ok = Test-LocalCredential $p.User $pw
            Log ("Rotated {0}: new password set{1}, login check {2}" -f $p.User, $(if ($script:StoreVault) { ' and saved to the vault' } else { ' (not stored here)' }), $(if ($ok) { 'PASSED' } else { 'could not be verified' })) 'ACTION'
        } catch { Log "Failed to rotate $($p.User): $_" 'ALERT' }
    }
    Show-FreshPasswords
    Log 'Check Hermes NOW to confirm scored services still pass.' 'WARN'
}
function Show-Passwords {
    $latest = Get-VaultLatest
    if ($latest.Count -eq 0) { Write-Host 'Nothing stored. Passwords are only kept on this machine if you turn storing on (V); otherwise they were shown once at rotation.'; return }
    [Console]::WriteLine('')
    [Console]::WriteLine(('{0,-30} {1,-20} {2,-20} {3}' -f 'User', 'Password', 'Set', 'Note'))
    foreach ($k in @($latest.Keys | Sort-Object)) {
        $r = $latest[$k]
        [Console]::WriteLine(('{0,-30} {1,-20} {2,-20} {3}' -f $r.user, $r.password, $r.time, $r.note))
    }
    [Console]::WriteLine('')
    Write-Host '(shown directly on the console so PowerShell transcripts and logs do not capture them; clear the screen when done)' -ForegroundColor DarkGray
    if (Confirm-YN 'Copy one password to the clipboard?' $false) {
        $u = Ask 'Which user'
        if ($latest.ContainsKey($u)) {
            if (Copy-SecretToClipboard $latest[$u].password) { Read-Host 'Copied. Paste it, then press Enter to clear the clipboard' | Out-Null; Clear-SecretClipboard; Write-Host 'Clipboard cleared.' }
            else { Write-Host 'Could not use the clipboard.' }
        }
    }
}
function Invoke-TestLogin {
    $latest = Get-VaultLatest
    $u = Ask 'User to test'
    if (-not $latest.ContainsKey($u)) { Write-Host 'No vault entry for that user.'; return }
    if (Test-LocalCredential $u $latest[$u].password) { Log "Vault password for $u is VALID on this machine." 'OK' }
    else { Log "Vault password for $u was REJECTED (changed by someone else? account locked?)." 'ALERT' }
}
function Invoke-ShellAs {
    $latest = Get-VaultLatest
    $u = Ask 'Open a PowerShell window as which user'
    if (-not $latest.ContainsKey($u)) { Write-Host 'No vault entry for that user.'; return }
    $acct = if ($u -match '\\') { $u } else { "$env:COMPUTERNAME\$u" }
    $cred = New-Object PSCredential($acct, (ConvertTo-Secure $latest[$u].password))
    try {
        Start-Process powershell.exe -Credential $cred -WorkingDirectory "$env:windir\System32" -ArgumentList '-NoExit', '-Command', 'whoami; hostname'
        Log "Opened a PowerShell window as $u (it may be non-elevated; use Start-Process powershell -Verb RunAs inside it)." 'ACTION'
    } catch {
        Log "Could not start as $u : $_" 'WARN'
        [Console]::WriteLine("Fallback: runas /user:$acct powershell    (password: " + $latest[$u].password + ")")
    }
    [Console]::WriteLine("For the console login screen type:  $acct  /  " + $latest[$u].password)
}
function Invoke-RestorePrevPw {
    $u = Ask 'Restore an earlier password for which user'
    $hist = @(); foreach ($r in (Get-VaultRows)) { if ($r.user -eq $u) { $hist += $r } }
    if ($hist.Count -lt 2) { Write-Host 'No earlier password recorded for that user (the original password was never captured).'; return }
    $i = 0; foreach ($h in $hist) { $i++; [Console]::WriteLine(('  {0}) {1}  {2}  [{3}]' -f $i, $h.time, $h.password, $h.note)) }
    $pick = Select-Indexes 'Which entry' $hist.Count
    if ($pick.Count -ne 1) { return }
    $pw = $hist[$pick[0] - 1].password
    if (Confirm-Yes "Set $u back to that password?") {
        try {
            if ($u -match '\\' -and (($u -split '\\', 2)[0] -ine $env:COMPUTERNAME)) { Set-DomainPasswordBySam (($u -split '\\', 2)[1]) $pw }
            else { Set-LocalUser -Name $u -Password (ConvertTo-Secure $pw) -ErrorAction Stop }
            Add-Vault $u $pw 'restored earlier'; Log "Restored earlier password for $u" 'ACTION'
        } catch { Log "Failed: $_" 'ALERT' }
    }
}
function Invoke-DisableAccount {
    $u = Ask 'Account to disable'
    if (-not $u) { return }
    if (Test-Protected $u) { Log "REFUSED: $u is out of scope (rule 6)." 'ALERT'; return }
    if ($u -ieq $env:USERNAME) { Log 'Refusing to disable the account you are using.' 'ALERT'; return }
    if (Confirm-Yes "Disable local account $u (reversible via the undo journal)?") {
        try { Disable-LocalUser -Name $u -ErrorAction Stop; [void](Add-Journal 'user' @{ name = $u }); Log "Disabled $u" 'ACTION' } catch { Log "Failed: $_" 'ALERT' }
    }
}
function Invoke-RemoveAdmin {
    $u = Ask 'Account to remove from local Administrators'
    if (-not $u) { return }
    if (Test-Protected $u) { Log "REFUSED: $u is out of scope (rule 6)." 'ALERT'; return }
    if (Confirm-Yes "Remove $u from Administrators? (re-add with: net localgroup Administrators $u /add)") {
        try { Remove-LocalGroupMember -Group 'Administrators' -Member $u -ErrorAction Stop; Log "Removed $u from Administrators" 'ACTION' } catch { Log "Failed: $_" 'ALERT' }
    }
}

# ============================================================================================
#  DOMAIN ACCOUNTS (Active Directory on pitwall). Needs a domain-joined machine and an account that may reset passwords.
#  Uses built-in .NET directory classes, so RSAT / the ActiveDirectory module is NOT required.
#  A domain password is shared by every machine: rotate from ONE machine only, the vault on the others goes stale.
# ============================================================================================
$script:ExpectedDomAdmins = @('principal', 'sportingdir', 'chiefeng', 'strategist')
$script:ExpectedDomUsers  = @('principal', 'sportingdir', 'chiefeng', 'strategist', 'pitcrew', 'mechanic', 'analyst', 'driver', 'tireman', 'fuelman')
$script:DomBuiltin        = @('administrator', 'krbtgt', 'guest', 'whiteteam', 'blackteam')
$script:DomCred           = $null

function Test-DomainJoined { try { return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { return $false } }
function Get-DomainDns { return [string](Get-CimInstance Win32_ComputerSystem).Domain }
function Get-DomainNetbios {
    try {
        $d = Get-CimInstance Win32_NTDomain -ErrorAction Stop | Where-Object { $_.DomainName -and $_.DnsForestName } | Select-Object -First 1
        if ($d) { return [string]$d.DomainName }
    } catch { }
    return ((Get-DomainDns) -split '\.')[0].ToUpper()
}
function Get-DomainBaseDn { return ('DC=' + ((Get-DomainDns) -split '\.' -join ',DC=')) }
function New-DomEntry {
    param([string]$Path)
    if ($script:DomCred) {
        return (New-Object System.DirectoryServices.DirectoryEntry($Path, $script:DomCred.UserName, $script:DomCred.GetNetworkCredential().Password))
    }
    return (New-Object System.DirectoryServices.DirectoryEntry($Path))
}
function Get-Prop { param($Res, [string]$Name) if ($Res.Properties[$Name].Count -gt 0) { return $Res.Properties[$Name][0] } return $null }
function Get-DomainUsers {
    $dns = Get-DomainDns
    $root = New-DomEntry ('LDAP://' + $dns + '/' + (Get-DomainBaseDn))
    $s = New-Object System.DirectoryServices.DirectorySearcher($root)
    $s.Filter = '(&(objectCategory=person)(objectClass=user))'
    $s.PageSize = 500
    foreach ($p in 'samaccountname', 'distinguishedname', 'useraccountcontrol', 'memberof', 'pwdlastset') { [void]$s.PropertiesToLoad.Add($p) }
    $out = @()
    foreach ($r in $s.FindAll()) {
        $sam = [string](Get-Prop $r 'samaccountname')
        if (-not $sam) { continue }
        $uac = [int](Get-Prop $r 'useraccountcontrol')
        $groups = @($r.Properties['memberof'] | ForEach-Object { (([string]$_ -split ',')[0]) -replace '^CN=', '' })
        $pls = Get-Prop $r 'pwdlastset'
        $pwset = $null
        if ($pls -and [int64]$pls -gt 0) { try { $pwset = [DateTime]::FromFileTime([int64]$pls) } catch { } }
        $isAdmin = [bool]($groups | Where-Object { $_ -match '^(Domain Admins|Enterprise Admins|Administrators|Schema Admins)$' })
        $out += [pscustomobject]@{ Sam = $sam; DN = [string](Get-Prop $r 'distinguishedname'); Enabled = (($uac -band 2) -eq 0); Admin = $isAdmin; Groups = ($groups -join ';'); PwdSet = $pwset }
    }
    return $out
}
# Query the directory as the current login; if that fails, ask once for a domain account (DOMAIN\name) that may reset passwords.
function Get-DomUsersSafe {
    try { return @(Get-DomainUsers) }
    catch {
        Log ('Directory query with the current login failed: ' + $_.Exception.Message) 'WARN'
        if ($script:DomCred) { $script:DomCred = $null; return $null }
        Write-Host 'Enter a domain account (DOMAIN\name) that is allowed to reset passwords.'
        $script:DomCred = Get-Credential
        if (-not $script:DomCred) { return $null }
        try { return @(Get-DomainUsers) }
        catch { Log ('Still failed: ' + $_.Exception.Message) 'ALERT'; $script:DomCred = $null; return $null }
    }
}
function Test-DomainCredential {
    param([string]$Sam, [string]$Pw)
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, (Get-DomainDns))
        return $ctx.ValidateCredentials($Sam, $Pw)
    } catch { return $false }
}
function Set-DomainPw {
    param([string]$DN, [string]$Pw)
    $e = New-DomEntry ('LDAP://' + (Get-DomainDns) + '/' + $DN)
    [void]$e.Invoke('SetPassword', $Pw)
    $e.CommitChanges()
}
function Set-DomainPasswordBySam {
    param([string]$Sam, [string]$Pw)
    $us = Get-DomUsersSafe
    if (-not $us) { throw 'Directory not reachable' }
    $t = @($us | Where-Object { $_.Sam -ieq $Sam }) | Select-Object -First 1
    if (-not $t) { throw "Domain user $Sam not found" }
    Set-DomainPw $t.DN $Pw
}
function Get-DomSessionUser {
    if ($script:DomCred) {
        $n = $script:DomCred.UserName
        if ($n -match '\\') { return (($n -split '\\', 2)[1]).ToLower() }
        return (($n -split '@')[0]).ToLower()
    }
    if ($env:USERDOMAIN -and ($env:USERDOMAIN -ine $env:COMPUTERNAME)) { return $env:USERNAME.ToLower() }
    return $null
}
function Show-DomainAudit {
    if (-not (Test-DomainJoined)) { Write-Host 'This machine is not domain-joined: there are no domain accounts to audit here.' -ForegroundColor Yellow; return }
    $us = Get-DomUsersSafe
    if (-not $us) { Log 'Could not read the domain directory.' 'ALERT'; return }
    $rows = foreach ($u in $us) {
        $n = $u.Sam.ToLower()
        $st = 'ok'
        if ($script:DomBuiltin -contains $n) { $st = 'builtin/out-of-scope' }
        elseif ($script:ExpectedDomUsers -notcontains $n) { $st = 'UNEXPECTED ACCOUNT' }
        if ($u.Admin -and ($script:ExpectedDomAdmins -notcontains $n) -and ($script:DomBuiltin -notcontains $n)) { $st = 'UNEXPECTED ADMIN' }
        [pscustomobject]@{ Name = $u.Sam; Enabled = $u.Enabled; Admin = $u.Admin; PwdLastSet = $u.PwdSet; Status = $st }
    }
    Show-Text ($rows | Sort-Object Name | Format-Table -AutoSize)
    foreach ($r in @($rows | Where-Object { $_.Status -like 'UNEXPECTED*' })) { Log ('DOMAIN {0}: {1} (enabled={2})' -f $r.Status, $r.Name, $r.Enabled) 'ALERT' }
}
function Invoke-DomainRotate {
    param([string[]]$Only)
    if (-not (Test-DomainJoined)) { Write-Host 'This machine is not domain-joined: nothing to rotate here.' -ForegroundColor Yellow; return }
    Write-Host 'DOMAIN password change. It affects every machine and service that uses these accounts, including Hermes AD checks.' -ForegroundColor Yellow
    Write-Host 'Do this from ONE machine only. Vault entries made on your other machines will be out of date afterwards.' -ForegroundColor Yellow
    if (-not (Confirm-YN 'Continue?' $false)) { return }
    if (-not (Test-Path $script:NoRotateFile)) { Write-Host 'First, tell me which accounts must NOT be rotated.'; Set-NoRotate }
    $no = @(Get-NoRotate | ForEach-Object { (($_ -split '\\')[-1]).ToLower() })
    $us = Get-DomUsersSafe
    if (-not $us) { Log 'Could not read the domain directory (no rights, or the domain controller is unreachable).' 'ALERT'; return }
    $me = Get-DomSessionUser
    $nb = Get-DomainNetbios
    $plan = @()
    foreach ($u in $us) {
        $n = $u.Sam.ToLower()
        if (-not $u.Enabled) { continue }
        if (Test-Protected $u.Sam) { continue }                                   # rule 6
        if ($n -in 'krbtgt', 'guest') { continue }
        if ($n -eq 'administrator' -and -not $Only) { continue }                  # built-in domain admin: only when named explicitly
        if ($Only -and ($Only | ForEach-Object { (($_ -split '\\')[-1]).ToLower() }) -notcontains $n) { continue }
        if ($no -contains $n) { Log "Skipping $($u.Sam): on the never-rotate list" 'INFO'; continue }
        $dep = Get-AccountDependents $u.Sam
        $plan += [pscustomobject]@{ User = $u.Sam; DN = $u.DN; Admin = $u.Admin; InUseByThisSession = ($me -and $n -eq $me); Dependents = ($dep -join ' ') }
    }
    if (-not $plan) { Log 'Nothing eligible to rotate.' 'WARN'; return }
    if ($script:StoreVault -and -not (Unlock-Vault)) { Log 'Vault could not be unlocked: nothing was changed.' 'ALERT'; return }
    $plan = @($plan | Sort-Object InUseByThisSession)                              # the account used for this session goes last
    Write-Host 'DOMAIN accounts that will get a NEW random password:'
    Show-Text ($plan | Select-Object User, Admin, InUseByThisSession, Dependents | Format-Table -AutoSize)
    if ($plan | Where-Object { $_.Dependents }) { Write-Host 'Accounts with Dependents run a service/task on THIS machine: it will stop working until you update the stored password.' -ForegroundColor Yellow }
    if (-not (Confirm-Yes 'Rotate these DOMAIN accounts now?')) { return }
    foreach ($p in $plan) {
        if ($p.User -ieq 'administrator') { if (-not (Confirm-YN '  Really rotate the built-in domain Administrator?' $false)) { continue } }
        if ($p.Dependents) {
            if (-not (Confirm-YN "  $($p.User) is used by [$($p.Dependents)]. Rotate anyway?" $false)) { Log "Skipped $($p.User)" 'INFO'; continue }
        }
        $pw = New-Pw
        try {
            Set-DomainPw $p.DN $pw
            Save-NewPw "$nb\$($p.User)" $pw 'domain rotated'
            $ok = Test-DomainCredential $p.User $pw
            Log ('Rotated DOMAIN {0}\{1}: new password set{2}, login check {3}' -f $nb, $p.User, $(if ($script:StoreVault) { ' and saved to the vault' } else { ' (not stored here)' }), $(if ($ok) { 'PASSED' } else { 'could not be verified' })) 'ACTION'
        } catch { Log "Failed to rotate DOMAIN $($p.User): $($_.Exception.Message)" 'ALERT' }
    }
    Show-FreshPasswords
    Log 'Check Hermes NOW (AD and anything that logs in with a domain account).' 'WARN'
}

function Invoke-AccountsMenu {
    while ($true) {
        Clear-Host
        Write-Host '=== ACCOUNTS ===' -ForegroundColor Cyan
        Write-Host ' 1) Audit local accounts (no changes)'
        Write-Host ' 2) Rotate passwords for all eligible accounts'
        Write-Host ' 3) Rotate password for ONE account'
        Write-Host (' V) Store passwords on this machine: ' + $(if ($script:StoreVault) { 'ON (encrypted vault)' } else { 'OFF - shown once, you record them (safer if Red is already on the box)' })) -ForegroundColor Yellow
        Write-Host ' 4) Show stored passwords (only if storing was ON)'
        Write-Host ' 5) Test that a vault password logs in'
        Write-Host ' 6) Open a PowerShell window as an account (uses vault password)'
        Write-Host ' 7) Put back an earlier password for an account'
        Write-Host ' 8) Disable an account (reversible)'
        Write-Host ' 9) Remove an account from Administrators'
        Write-Host ' N) Set the never-rotate list (accounts Hermes depends on)'
        Write-Host ' A) Audit DOMAIN accounts (no changes)'
        Write-Host ' D) Rotate passwords for all eligible DOMAIN accounts'
        Write-Host ' E) Rotate password for ONE DOMAIN account'
        Write-Host ' 0) Back'
        switch ((Read-Host 'Select').Trim().ToLower()) {
            '1' { Show-AccountAudit; Pause-Menu }
            '2' { Invoke-Rotate; Pause-Menu }
            '3' { $u = Ask 'Account name'; if ($u) { Invoke-Rotate -Only @($u) }; Pause-Menu }
            '4' { Show-Passwords; Pause-Menu }
            '5' { Invoke-TestLogin; Pause-Menu }
            '6' { Invoke-ShellAs; Pause-Menu }
            '7' { Invoke-RestorePrevPw; Pause-Menu }
            '8' { Invoke-DisableAccount; Pause-Menu }
            '9' { Invoke-RemoveAdmin; Pause-Menu }
            'v' { Toggle-StoreVault; Pause-Menu }
            'n' { Set-NoRotate; Pause-Menu }
            'a' { Show-DomainAudit; Pause-Menu }
            'd' { Invoke-DomainRotate; Pause-Menu }
            'e' { $u = Ask 'Domain account name (without DOMAIN\)'; if ($u) { Invoke-DomainRotate -Only @($u) }; Pause-Menu }
            '0' { return }
        }
    }
}

# ============================================================================================
#  TAMPER DEFENSE: services, registry, event logs, and "what changed / who did it"
#  Common Red Team moves covered here (general techniques, not a record of any past event):
#    - disable a service (Start=4), change its ImagePath/logon account, or lock its permissions (SDDL) so you cannot start it
#    - plant FailureCommand / ServiceDll so SYSTEM runs their code when a service fails or starts
#    - clear or disable event logs, shrink them, or turn off auditing so there is nothing to read
#    - flip registry values: firewall off, Defender off, WDigest, UAC, Winlogon Shell/Userinit, AppInit_DLLs, SMB/anonymous settings
# ============================================================================================
function Get-EvData {
    param($Event)
    $x = [xml]$Event.ToXml(); $h = @{}
    foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = $d.'#text' } }
    return $h
}

# ---------------- Service guard: enable + start, with dependencies ----------------
$script:DefaultSddl = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'

function Reset-ServiceSddl {
    param([string]$Name)
    $old = ((sc.exe sdshow $Name 2>&1) | Where-Object { $_ -match '^D:' }) -join ''
    $null = sc.exe sdset $Name $script:DefaultSddl 2>&1
    if ($LASTEXITCODE -ne 0) {
        Log "Direct sdset on $Name was refused; retrying as SYSTEM." 'WARN'
        Invoke-AsSystem "sc sdset $Name $($script:DefaultSddl)"
    }
    if ($old) { [void](Add-Journal 'sddl' @{ name = $Name; old = $old }) }
    Log "Reset permissions on service $Name to the standard Windows descriptor." 'ACTION'
}

function Repair-OneService {
    param([string]$Name, [bool]$Crit, [bool]$ResetAcl, [bool]$SetFailure, [int]$Depth = 0)
    if ($Depth -gt 4) { return }
    if (Test-DatadogName $Name) { return }
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path -LiteralPath $key)) { Log "Service '$Name' has no registry key (deleted, or just a dependency group)." 'WARN'; return }

    foreach ($dep in Get-SvcDeps $Name) {
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$dep") { Repair-OneService $dep $false $ResetAcl $false ($Depth + 1) }
    }

    $start = Get-SvcStart $Name
    $oldState = ''
    $s0 = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($s0) { $oldState = "$($s0.Status)" }
    $needCfg = ($start -eq 4) -or ($Crit -and $start -notin 0, 1, 2)
    if ($needCfg) {
        $mode = if ($Crit) { 'auto' } else { 'demand' }
        sc.exe config $Name start= $mode 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -and $ResetAcl) { Reset-ServiceSddl $Name; sc.exe config $Name start= $mode 2>&1 | Out-Null }
        if ($LASTEXITCODE -eq 0) {
            [void](Add-Journal 'scstart' @{ name = $Name; oldStart = $start; oldState = $oldState })
            Log "Service $Name startup: $(Get-ScModeWord $start) -> $mode" 'ACTION'
        } else {
            Log "Could not change startup type of $Name (access denied?). Try again with the 'reset permissions' answer = y." 'ALERT'
        }
    }

    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $running = $false
    if ($s -and $s.Status -eq 'Running') { $running = $true }
    else {
        $err = $null
        try { Start-Service -Name $Name -ErrorAction Stop } catch { $err = $_.Exception.Message }
        if ($err -match 'Cannot open|Access is denied|denied' -and $ResetAcl) {
            Reset-ServiceSddl $Name
            $err = $null
            try { Start-Service -Name $Name -ErrorAction Stop } catch { $err = $_.Exception.Message }
        }
        if ($err -and -not $s) { sc.exe start $Name 2>&1 | Out-Null }       # kernel drivers are not returned by Get-Service
        Start-Sleep -Milliseconds 800
        $q = (sc.exe query $Name 2>&1) -join ' '
        $running = ($q -match 'RUNNING')
        if (-not $running -and $err) { Log "Service $Name did not start: $err  (see System log events 7000/7001/7023/7024, or run Tamper > Service audit)" 'ALERT' }
    }
    if ($running) { Log "Service $Name is running." 'OK' }
    elseif ($Crit) { Log "Service $Name is NOT running." 'ALERT' }

    if ($Crit -and $SetFailure -and $s) {
        sc.exe failure $Name reset= 86400 actions= restart/5000/restart/5000/restart/5000 2>&1 | Out-Null
        Log "Set $Name to restart automatically on failure." 'ACTION'
    }
}

function Invoke-ServiceGuard {
    $cfg = $script:RoleCfg[$script:Role]
    Write-Host 'Enable and start services (also fixes disabled dependencies).'
    Write-Host ' 1) Role service(s) + Windows core set      <- recommended'
    Write-Host ' 2) Role service(s) only'
    Write-Host ' 3) Choose from services that are stopped or disabled'
    Write-Host ' 4) Type service names'
    Write-Host ' 5) Remote-access services (RDP + WinRM)'
    $pick = Ask 'Select' '1'
    $names = @(); $crit = $true
    switch ($pick) {
        '1' { $names = @($cfg.Services) + $script:CoreServices }
        '2' { $names = @($cfg.Services) }
        '3' {
            $list = @(Get-CimInstance Win32_Service | Where-Object { $_.State -ne 'Running' -and $_.StartMode -ne 'Manual' -or $_.StartMode -eq 'Disabled' } |
                Where-Object { -not (Test-DatadogName $_.Name) } | Sort-Object Name)
            if (-not $list) { Write-Host 'Nothing stopped/disabled.'; return }
            $i = 0; foreach ($s in $list) { $i++; Write-Host ('{0,3}) {1,-28} {2,-9} {3}' -f $i, $s.Name, $s.StartMode, $s.State) }
            $sel = Select-Indexes 'Numbers (e.g. 1,3,5-7 or all)' $list.Count
            $names = @($sel | ForEach-Object { $list[$_ - 1].Name }); $crit = $false
        }
        '4' { $names = @((Ask 'Service names, comma separated') -split '[,\s]+' | Where-Object { $_ }) }
        '5' { $names = $script:AccessServices }
    }
    $names = @($names | Select-Object -Unique)
    if (-not $names) { return }
    $acl = Confirm-YN 'If a service refuses to start/config because its permissions were tampered with, reset them to the Windows default?' $true
    $fail = if ($crit) { Confirm-YN 'Also set auto-restart on failure for these services?' $true } else { $false }
    foreach ($n in $names) { Repair-OneService $n $crit $acl $fail }
    Write-Host ''
    Show-Text (Get-CimInstance Win32_Service | Where-Object { $names -contains $_.Name } | Select-Object Name, StartMode, State, StartName | Format-Table -AutoSize)
    Log 'Re-check the Hermes dashboard. If a service keeps breaking, run Tamper > What changed to see who is doing it.' 'WARN'
}

# ---------------- Service tamper audit ----------------
function Invoke-ServiceAudit {
    Write-Host '--- Core / role / access services ---'
    $cfg = $script:RoleCfg[$script:Role]
    $watch = @($cfg.Services) + $script:CoreServices + $script:AccessServices | Select-Object -Unique
    $rows = foreach ($n in $watch) {
        $k = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
        if (-not (Test-Path $k)) { [pscustomobject]@{ Name = $n; Start = '-'; State = 'NO KEY'; Logon = ''; Image = ''; Sig = '' }; continue }
        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
        $img = Get-RegRaw $k 'ImagePath'; $ex = Get-ExePath $img
        [pscustomobject]@{ Name = $n; Start = (Get-ScModeWord (Get-SvcStart $n)); State = "$($svc.Status)"; Logon = (Get-RegRaw $k 'ObjectName'); Image = $img; Sig = (Get-SigInfo $ex) }
    }
    Show-Text ($rows | Format-Table -AutoSize -Wrap)

    $base = @{}
    if (Test-Path $script:SvcBase) { foreach ($b in Import-Csv $script:SvcBase) { $base[$b.Name] = $b } }
    Write-Host '--- Scanning every service in the registry ---'
    $count = 0
    foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue) {
        $n = $k.PSChildName
        if (Test-DatadogName $n) { continue }
        $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
        if (-not $p.ImagePath -and $null -eq $p.Start) { continue }
        if ($p.FailureCommand) { Log "Service $n has a FailureCommand (runs as SYSTEM when it fails): $($p.FailureCommand)" 'ALERT'; $count++ }
        $dll = (Get-ItemProperty -LiteralPath "$($k.PSPath)\Parameters" -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll
        if ($dll) {
            $dp = Get-ExePath $dll
            if ($dp -and ($dp -notmatch '(?i)^[A-Z]:\\Windows\\(System32|SysWOW64)\\' -or (Get-SigInfo $dp) -ne 'microsoft')) {
                Log "Service $n loads ServiceDll $dp (signature: $(Get-SigInfo $dp))" 'ALERT'; $count++
            }
        }
        $ex = Get-ExePath $p.ImagePath
        if ($p.Start -in 0, 1, 2 -and $ex) {
            $sig = Get-SigInfo $ex
            if ($ex -match $script:SusPath -and $ex -notmatch $script:OkPath) { Log "Auto-start service $n runs from a user-writable path: $ex" 'ALERT'; $count++ }
            elseif ($sig -eq 'missing') { Log "Auto-start service $n points at a missing file: $ex" 'ALERT'; $count++ }
            elseif ($sig -eq 'unsigned' -and $ex -notmatch '(?i)\\Windows\\') { Log "Auto-start service $n has an unsigned binary: $ex" 'WARN' }
        }
        if ($base.Count -gt 0) {
            if (-not $base.ContainsKey($n)) { Log "Service $n is NEW since the service baseline ($($p.ImagePath))" 'WARN'; $count++ }
            else {
                $b = $base[$n]
                if ("$($p.Start)" -ne $b.Start) { Log "Service $n startup changed: $($b.Start) -> $($p.Start) (0 boot,1 system,2 auto,3 manual,4 disabled)" 'ALERT'; $count++ }
                if ("$($p.ImagePath)" -ne $b.ImagePath) { Log "Service $n ImagePath changed: $($b.ImagePath) -> $($p.ImagePath)" 'ALERT'; $count++ }
                if ("$($p.ObjectName)" -ne $b.ObjectName) { Log "Service $n logon account changed: $($b.ObjectName) -> $($p.ObjectName)" 'ALERT'; $count++ }
            }
        }
    }
    if ($count -eq 0) { Log 'Service scan found nothing odd.' 'OK' }
    $q = if ($base.Count -eq 0) { 'No service baseline yet. Save one now?' } else { 'Replace the saved service baseline with the current state?' }
    if (Confirm-YN $q ($base.Count -eq 0)) {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            [pscustomobject]@{ Name = $_.PSChildName; Start = "$($p.Start)"; ImagePath = "$($p.ImagePath)"; ObjectName = "$($p.ObjectName)" }
        } | Export-Csv $script:SvcBase -NoTypeInformation -Encoding ASCII
        Log "Service baseline saved to $script:SvcBase" 'ACTION'
    }
}

# ---------------- Registry watch ----------------
$script:RegWatch = @(
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile';   N = 'EnableFirewall'; Good = '1'; K = 'DWord'; Why = 'Windows Firewall switched off (domain profile)' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; N = 'EnableFirewall'; Good = '1'; K = 'DWord'; Why = 'Windows Firewall switched off (private profile)' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile';   N = 'EnableFirewall'; Good = '1'; K = 'DWord'; Why = 'Windows Firewall switched off (public profile)' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; N = 'DisableAntiSpyware'; Good = '0'; Absent = $true; K = 'DWord'; Manual = $true; Why = 'Defender turned off by policy (watch only: ask White Team before turning it on, rule 12)' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; N = 'DisableRealtimeMonitoring'; Good = '0'; Absent = $true; K = 'DWord'; Manual = $true; Why = 'Defender real-time protection off (watch only: ask White Team before turning it on, rule 12)' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'EnableLUA'; Good = '1'; K = 'DWord'; Why = 'UAC disabled' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'LocalAccountTokenFilterPolicy'; K = 'DWord'; Why = '1 lets remote local admins bypass UAC filtering (lateral movement)' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'FilterAdministratorToken'; K = 'DWord'; Why = 'Built-in Administrator token filtering' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; N = 'UseLogonCredential'; Good = '0'; Absent = $true; K = 'DWord'; Why = '1 keeps cleartext passwords in memory' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'RunAsPPL'; K = 'DWord'; Why = 'LSASS protection' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'LimitBlankPasswordUse'; Good = '1'; K = 'DWord'; Why = 'Allows blank-password network logons if 0' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'NoLMHash'; Good = '1'; K = 'DWord'; Why = 'Weak LM hashes stored if 0' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'RestrictAnonymous'; K = 'DWord'; Why = 'Anonymous enumeration of accounts/shares' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'LmCompatibilityLevel'; K = 'DWord'; Why = 'NTLM version allowed' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'Authentication Packages'; K = 'Multi'; Why = 'Extra auth package = credential theft DLL' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'Notification Packages'; K = 'Multi'; Why = 'Password filter DLL captures new passwords' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; N = 'Security Packages'; K = 'Multi'; Why = 'Extra security package DLL' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; N = 'Shell'; Good = 'explorer.exe'; K = 'String'; Why = 'Runs attacker program at every logon' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; N = 'Userinit'; Good = 'C:\Windows\system32\userinit.exe,'; K = 'String'; Why = 'Runs attacker program at every logon' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; N = 'AppInit_DLLs'; Good = ''; Absent = $true; K = 'String'; Why = 'DLL injected into every GUI process' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; N = 'LoadAppInit_DLLs'; K = 'DWord'; Why = 'Enables AppInit DLL injection' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; N = 'BootExecute'; K = 'Multi'; Why = 'Runs a program before Windows loads' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; N = 'fDenyTSConnections'; K = 'DWord'; Why = '1 = RDP disabled (you may need RDP to reach cloud boxes)' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; N = 'AllowBasic'; K = 'DWord'; Why = 'WinRM Basic auth policy' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; N = 'AllowUnencryptedTraffic'; K = 'DWord'; Why = 'WinRM unencrypted policy' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; N = 'SMB1'; Good = '0'; Absent = $true; K = 'DWord'; Why = 'SMBv1 re-enabled' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; N = 'RestrictNullSessAccess'; Good = '1'; K = 'DWord'; Why = 'Anonymous access to shares/pipes' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; N = 'NullSessionShares'; K = 'Multi'; Why = 'Shares reachable without credentials' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'; N = 'MaxSize'; K = 'DWord'; Why = 'Security log shrunk so old events vanish' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'; N = 'Retention'; K = 'DWord'; Why = 'Retention changed so the log fills and stops recording' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security'; N = 'File'; K = 'String'; Why = 'Log file redirected' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'; N = 'Start'; Good = '2'; K = 'DWord'; Why = 'Event Log service disabled for next boot' }
    @{ P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; N = 'ProcessCreationIncludeCmdLine_Enabled'; K = 'DWord'; Why = 'Command-line logging turned off' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; N = 'EnableScriptBlockLogging'; K = 'DWord'; Why = 'PowerShell logging turned off' }
    @{ P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; N = 'AlwaysInstallElevated'; Good = '0'; Absent = $true; K = 'DWord'; Why = 'Any MSI installs as SYSTEM' }
    @{ P = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'; N = 'AlwaysInstallElevated'; Good = '0'; Absent = $true; K = 'DWord'; Why = 'Any MSI installs as SYSTEM' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; N = 'NameServer'; K = 'String'; Why = 'DNS servers redirected' }
    @{ P = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient'; N = 'DllName'; K = 'String'; Why = 'Time provider DLL hijack' }
)

function Get-RegWatchStatus {
    $base = $null
    if (Test-Path $script:RegBase) { $base = Get-Content $script:RegBase -Raw | ConvertFrom-Json }
    $rows = @()
    foreach ($w in $script:RegWatch) {
        $key = $w.P + '|' + $w.N
        $cur = Get-RegRaw $w.P $w.N
        $b = $null; $hasBase = $false
        if ($base) { $prop = $base.PSObject.Properties[$key]; if ($prop) { $hasBase = $true; $b = $prop.Value } }
        $curS = if ($null -eq $cur) { '<absent>' } else { $cur }
        $status = 'ok'
        if ($w.ContainsKey('Good')) {
            $okGood = ($curS -eq $w.Good) -or ($w.Absent -and ($curS -eq '<absent>' -or $curS -eq '0' -or $curS -eq ''))
            if (-not $okGood) { $status = 'DEVIATES' }
        }
        if ($status -eq 'ok' -and $hasBase -and ($curS -ne $b)) { $status = 'CHANGED' }
        $rows += [pscustomobject]@{ Item = $w; Cur = $curS; Base = $(if ($hasBase) { $b } else { '(no baseline)' }); Status = $status }
    }
    return $rows
}

function Invoke-RegWatch {
    Write-Host ' 1) Check now (compare with baseline and known-good values)'
    Write-Host ' 2) Save current values as the baseline'
    Write-Host ' 3) Check, then restore selected values'
    $m = Ask 'Select' '1'
    if ($m -eq '2') {
        $h = [ordered]@{}
        foreach ($w in $script:RegWatch) { $v = Get-RegRaw $w.P $w.N; $h[($w.P + '|' + $w.N)] = $(if ($null -eq $v) { '<absent>' } else { $v }) }
        $h | ConvertTo-Json | Set-Content $script:RegBase -Encoding ASCII
        Log "Registry baseline saved ($($script:RegWatch.Count) values). Baselines taken after Red got in can contain their changes: the 'known-good' column still flags the obvious ones." 'ACTION'
        return
    }
    $rows = @(Get-RegWatchStatus)
    $bad = @($rows | Where-Object { $_.Status -ne 'ok' })
    $i = 0
    foreach ($r in $bad) {
        $i++
        $lvl = if ($r.Status -eq 'DEVIATES') { 'ALERT' } else { 'WARN' }
        Log ("#{0} {1}: {2}\{3} = {4}   (baseline: {5})  -- {6}" -f $i, $r.Status, $r.Item.P, $r.Item.N, $r.Cur, $r.Base, $r.Item.Why) $lvl
    }
    if (-not $bad) { Log "All $($rows.Count) watched registry values look fine." 'OK' }
    if (-not (Test-Path $script:RegBase)) { Write-Host 'No baseline saved yet: use option 2 once you trust the current state.' -ForegroundColor Yellow }
    if ($m -ne '3' -or -not $bad) { return }
    $sel = Select-Indexes 'Restore which numbers (blank = none)' $bad.Count
    foreach ($n in $sel) {
        $r = $bad[$n - 1]; $w = $r.Item
        if ($w.K -eq 'Multi') { Log "$($w.N) is multi-valued: fix it by hand (report only)." 'WARN'; continue }
        if ($w.Manual -and -not (Confirm-Yes 'This turns Defender protection back on. Rule 12 bans antivirus scanning or sending artifacts: ask White Team first. Continue?')) { continue }
        try {
            if ($w.ContainsKey('Good')) {
                if ($w.Good -eq '' -and $w.Absent) { Remove-RegJournal $w.P $w.N }
                else { $val = if ($w.K -eq 'DWord') { [int]$w.Good } else { $w.Good }; Set-RegJournal $w.P $w.N $val $w.K }
            } elseif ($r.Base -eq '<absent>') { Remove-RegJournal $w.P $w.N }
            elseif ($r.Base -ne '(no baseline)') { $val = if ($w.K -eq 'DWord') { [int]$r.Base } else { $r.Base }; Set-RegJournal $w.P $w.N $val $w.K }
            Log "Restored $($w.P)\$($w.N)" 'ACTION'
        } catch { Log "Could not restore $($w.P)\$($w.N): $_" 'ALERT' }
    }
}

# ---------------- Event log health, repair, mirror, extra channels, registry auditing ----------------
$script:LogChannels = @('Security', 'System', 'Application',
    'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-WinRM/Operational',
    'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-WMI-Activity/Operational',
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-Bits-Client/Operational')

function Get-TargetLogMB { param([string]$Ch) if ($Ch -eq 'Security') { return 512 } elseif ($Ch -match 'PowerShell') { return 256 } elseif ($Ch -eq 'System' -or $Ch -eq 'Application') { return 128 } else { return 64 } }

function Invoke-EventLogHealth {
    $svc = Get-Service EventLog -ErrorAction SilentlyContinue
    $st = Get-SvcStart 'EventLog'
    Log ("Windows Event Log service: {0}, startup value {1}" -f $svc.Status, $st) $(if ($svc.Status -eq 'Running' -and $st -eq 2) { 'OK' } else { 'ALERT' })
    $fix = @()
    $rows = foreach ($ch in $script:LogChannels) {
        $l = Get-WinEvent -ListLog $ch -ErrorAction SilentlyContinue
        if (-not $l) { [pscustomobject]@{ Channel = $ch; Enabled = 'n/a'; SizeMB = ''; MaxMB = ''; Mode = ''; Records = ''; LastWrite = 'channel not present' }; continue }
        if (-not $l.IsEnabled) { $fix += $ch; Log "Channel DISABLED: $ch" 'ALERT' }
        elseif ([math]::Round($l.MaximumSizeInBytes / 1MB) -lt (Get-TargetLogMB $ch) / 4) { $fix += $ch; Log "Channel $ch has a very small maximum size ($([math]::Round($l.MaximumSizeInBytes/1MB)) MB)" 'WARN' }
        if ("$($l.LogMode)" -ne 'Circular') { $fix += $ch; Log "Channel $ch retention mode is $($l.LogMode) (it can fill up and stop recording)" 'WARN' }
        [pscustomobject]@{ Channel = $ch; Enabled = $l.IsEnabled; SizeMB = [math]::Round($l.FileSize / 1MB, 1); MaxMB = [math]::Round($l.MaximumSizeInBytes / 1MB); Mode = "$($l.LogMode)"; Records = $l.RecordCount; LastWrite = $l.LastWriteTime }
    }
    Show-Text ($rows | Format-Table -AutoSize)

    Write-Host '--- Logs cleared or auditing tampered with (last 24 h) ---'
    $since = (Get-Date).AddHours(-24)
    $any = $false
    foreach ($q in @(@{ L = 'Security'; I = 1102 }, @{ L = 'System'; I = 104 }, @{ L = 'Security'; I = 4719 }, @{ L = 'Security'; I = 1100 })) {
        foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = $q.L; Id = $q.I; StartTime = $since } -ErrorAction SilentlyContinue) {
            $any = $true
            $x = [xml]$e.ToXml(); $ud = $x.Event.UserData.FirstChild
            $who = if ($ud.SubjectUserName) { $ud.SubjectUserName } else { (Get-EvData $e).SubjectUserName }
            $what = switch ($e.Id) { 1102 { 'Security log CLEARED' } 104 { "Log CLEARED ($($ud.Channel))" } 4719 { 'Audit policy changed' } 1100 { 'Event logging service shut down' } }
            Log ("{0} {1} by {2}" -f $e.TimeCreated.ToString('MM-dd HH:mm:ss'), $what, $who) 'ALERT'
        }
    }
    if (-not $any) { Log 'No log-clear or audit-policy-change events found.' 'OK' }

    Write-Host '--- Audit policy (subcategories that matter) ---'
    $ap = (auditpol /get /category:* 2>&1) -join "`n"
    foreach ($s in 'Process Creation', 'Logon', 'User Account Management', 'Security Group Management', 'Security System Extension', 'Other Object Access Events', 'Registry') {
        $m = [regex]::Match($ap, '(?m)^\s*' + [regex]::Escape($s) + '\s{2,}(.+)$')
        $v = if ($m.Success) { $m.Groups[1].Value.Trim() } else { '?' }
        Log ("auditpol {0}: {1}" -f $s, $v) $(if ($v -match 'No Auditing') { 'ALERT' } else { 'INFO' })
    }

    foreach ($w in $script:RegWatch | Where-Object { $_.P -match 'EventLog' }) {
        $c = Get-RegRaw $w.P $w.N
        if ($w.N -eq 'File' -and $c -and $c -notmatch '(?i)winevt\\logs') { Log "Security log file path redirected: $c" 'ALERT' }
    }

    Write-Host ''
    Write-Host 'Where to look when Event Viewer shows nothing:' -ForegroundColor Cyan
    Write-Host '  * Event Viewer > Windows Logs > Security/System/Application need admin; app-specific logs are under Applications and Services Logs'
    Write-Host '  * Service changes: System log, IDs 7040 (start type changed), 7036 (stopped/started), 7045 (new service), 7031/7034 (crashed)'
    Write-Host '  * Log cleared: Security 1102, System 104.  Who ran what: Security 4688 (needs process-creation auditing, option in Setup)'
    switch ($script:Role) {
        'smb'   { Write-Host '  * SMB: Applications and Services > Microsoft > Windows > SMBServer (Security/Operational); sessions: Get-SmbSession' }
        'iis'   { Write-Host '  * IIS: C:\inetpub\logs\LogFiles\W3SVC*\*.log and C:\Windows\System32\LogFiles\HTTPERR (plain files, not in Event Viewer)' }
        'winrm' { Write-Host '  * WinRM: Microsoft-Windows-WinRM/Operational and PowerShell/Operational (4104 script blocks)' }
    }

    if ($fix.Count -gt 0 -or $svc.Status -ne 'Running' -or $st -ne 2) {
        if (Confirm-YN 'Repair: enable disabled channels, restore sizes, set overwrite-when-full, and fix the service start value?' $true) {
            if ($st -ne 2) { Set-RegJournal 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' 'Start' 2 'DWord' }
            if ($svc.Status -ne 'Running') { Start-Service EventLog -ErrorAction SilentlyContinue }
            foreach ($ch in ($fix | Select-Object -Unique)) {
                wevtutil sl $ch /e:true /rt:false /ab:false /ms:$((Get-TargetLogMB $ch) * 1MB) 2>&1 | Out-Null
                Log "Repaired channel $ch" 'ACTION'
            }
        }
    }
}

function Invoke-LogMirror {
    param([int]$Minutes = 10, [switch]$Quiet)
    $ms = $Minutes * 60000
    $q = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    foreach ($ch in 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-WinRM/Operational', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-WMI-Activity/Operational') {
        $safe = $ch -replace '[\\/ ]', '_'
        $f = Join-Path "$script:Root\evtx" "$safe-$stamp.evtx"
        wevtutil epl $ch $f /q:$q /ow:true 2>&1 | Out-Null
        Get-ChildItem "$script:Root\evtx" -Filter "$safe-*.evtx" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 60 | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    if ($script:Role -eq 'iis' -and (Test-Path 'C:\inetpub\logs\LogFiles')) {
        robocopy 'C:\inetpub\logs\LogFiles' "$script:Root\evtx\iislogs" /E /XO /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
    }
    if (-not $Quiet) { Log "Copied the last $Minutes minutes of key logs to $script:Root\evtx (attackers clearing the live log cannot erase these copies)." 'ACTION' }
}

function Set-RegAudit {
    param([string]$Path)
    try {
        $acl = Get-Acl -Path $Path -Audit -ErrorAction Stop
        $rule = New-Object System.Security.AccessControl.RegistryAuditRule('Everyone', [System.Security.AccessControl.RegistryRights]'SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership',
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit', [System.Security.AccessControl.PropagationFlags]'None', [System.Security.AccessControl.AuditFlags]'Success')
        $acl.AddAuditRule($rule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        return $true
    } catch { Log "Could not audit $Path : $($_.Exception.Message)" 'WARN'; return $false }
}
function Invoke-ExtraAuditing {
    Log 'Enabling extra log channels...'
    foreach ($ch in $script:LogChannels) { wevtutil sl $ch /e:true 2>&1 | Out-Null }
    auditpol /set /subcategory:"Registry" /success:enable /failure:disable 2>&1 | Out-Null
    $cfg = $script:RoleCfg[$script:Role]
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy', 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog')
    foreach ($s in (@($cfg.Services) + $script:CoreServices + $script:AccessServices | Select-Object -Unique)) { $keys += "HKLM:\SYSTEM\CurrentControlSet\Services\$s" }
    $ok = 0
    foreach ($k in $keys) { if (Test-Path $k) { if (Set-RegAudit $k) { $ok++ } } }
    Log "Registry change auditing enabled on $ok keys. Changes now appear as Security event 4657 (who, which value, old and new data)." 'ACTION'
}

# ---------------- What changed, and who did it ----------------
function Invoke-ChangeTimeline {
    $m = [int](Ask 'Look back how many minutes' '60')
    $start = (Get-Date).AddMinutes(-$m)
    $script:tl = @()
    function Add-Row { param($T, $Src, $What, $Who) $script:tl += [pscustomobject]@{ Time = $T; Source = $Src; What = $What; Who = $Who } }

    $logon = @{}
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddHours(-12) } -MaxEvents 5000 -ErrorAction SilentlyContinue) {
        $d = Get-EvData $e
        if ($d.TargetLogonId) { $logon[$d.TargetLogonId] = "{0} type{1} from {2}" -f $d.TargetUserName, $d.LogonType, $d.IpAddress }
    }
    function Who { param($d) $w = $d.SubjectUserName; if ($d.SubjectLogonId -and $logon.ContainsKey($d.SubjectLogonId)) { $w += " [" + $logon[$d.SubjectLogonId] + "]" }; return $w }
    function Leaf { param($p) if ($p) { return (Split-Path $p -Leaf) } return '' }

    $crit = @(); foreach ($n in (@($script:RoleCfg[$script:Role].Services) + $script:CoreServices + $script:AccessServices)) { $s = Get-Service $n -ErrorAction SilentlyContinue; if ($s) { $crit += $s.DisplayName } }
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040, 7045, 7034, 7031, 7036, 104; StartTime = $start } -ErrorAction SilentlyContinue) {
        $msg = ($e.Message -split "`n")[0]
        if ($e.Id -eq 7036 -and -not ($crit | Where-Object { $msg -like "*$_*" })) { continue }
        if (Test-DatadogName $msg) { continue }
        Add-Row $e.TimeCreated 'System' ("[{0}] {1}" -f $e.Id, $msg) '(service events do not record who)'
    }
    $sec = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102, 4719, 4720, 4722, 4724, 4725, 4726, 4732, 4756, 4697, 4698, 4699, 4702, 4657, 4688; StartTime = $start } -ErrorAction SilentlyContinue
    $cmdRx = '(?i)\b(config|stop|disable|delete|sdset|failure|clear-log|Clear-EventLog|Set-Service|Stop-Service|Remove-Service|Set-ItemProperty|Remove-ItemProperty|auditpol|advfirewall|firewall|wevtutil|net\s+user|localgroup)\b|reg(\.exe)?\s+(add|delete)|\bcl\b'
    $toolRx = '(?i)\\(sc|net|net1|reg|wevtutil|schtasks|auditpol|netsh|icacls|takeown|bcdedit|wmic|powershell|pwsh|cmd|mshta|rundll32|regsvr32)\.exe$'
    foreach ($e in $sec) {
        $d = Get-EvData $e
        switch ($e.Id) {
            4688 {
                if ($d.NewProcessName -match $toolRx -and $d.CommandLine -match $cmdRx -and $d.CommandLine -notmatch 'BlueMenu|BlueOps' -and -not (Test-DatadogName $d.CommandLine)) {
                    Add-Row $e.TimeCreated 'Process' ("{0}  (parent {1})" -f $d.CommandLine, (Leaf $d.ParentProcessName)) (Who $d)
                }
            }
            4657 { if (-not (Test-DatadogName $d.ObjectName)) { Add-Row $e.TimeCreated 'Registry' ("{0}\{1}: {2} -> {3}  (by {4})" -f $d.ObjectName, $d.ObjectValueName, $d.OldValue, $d.NewValue, (Leaf $d.ProcessName)) (Who $d) } }
            1102 { Add-Row $e.TimeCreated 'Security' 'SECURITY LOG CLEARED' $d.SubjectUserName }
            4719 { Add-Row $e.TimeCreated 'Security' 'Audit policy changed' (Who $d) }
            default {
                $what = switch ($e.Id) { 4720 { 'Account created' } 4722 { 'Account enabled' } 4724 { 'Password reset' } 4725 { 'Account disabled' } 4726 { 'Account deleted' } 4732 { 'Added to local group' } 4756 { 'Added to universal group' } 4697 { 'Service installed' } 4698 { 'Scheduled task created' } 4699 { 'Scheduled task deleted' } 4702 { 'Scheduled task updated' } }
                Add-Row $e.TimeCreated 'Security' ("{0}: {1} {2}" -f $what, $d.TargetUserName, $d.TaskName) (Who $d)
            }
        }
    }
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $start } -ErrorAction SilentlyContinue) {
        if ($e.Message -match '(?i)Stop-Service|Set-Service|Clear-EventLog|Remove-EventLog|Disable-|Set-ItemProperty|Remove-ItemProperty|New-Service|FromBase64String|Invoke-Expression' -and $e.Message -notmatch 'BlueMenu|BlueOps') {
            $t = ($e.Message -replace '\s+', ' '); Add-Row $e.TimeCreated 'PowerShell' $t.Substring(0, [Math]::Min(200, $t.Length)) ''
        }
    }
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 140, 141; StartTime = $start } -ErrorAction SilentlyContinue) {
        Add-Row $e.TimeCreated 'Tasks' (($e.Message -split "`n")[0]) ''
    }
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001, 5007; StartTime = $start } -ErrorAction SilentlyContinue) {
        Add-Row $e.TimeCreated 'Defender' (($e.Message -split "`n")[0]) ''
    }
    if (-not $script:tl) {
        Write-Host 'No matching events. If you expected some: Tamper > Event log health (logs cleared/disabled?), and Setup > Visibility (process-creation auditing).' -ForegroundColor Yellow
        return
    }
    foreach ($r in $script:tl | Sort-Object Time) {
        $c = switch ($r.Source) { 'Process' { 'Red' } 'Registry' { 'Red' } 'Security' { 'Yellow' } default { 'Gray' } }
        Write-Host ("{0}  {1,-9} {2}" -f $r.Time.ToString('HH:mm:ss'), $r.Source, $r.What) -ForegroundColor $c
        if ($r.Who) { Write-Host ("{0}  {1,-9}   by: {2}" -f '        ', '', $r.Who) -ForegroundColor DarkGray }
    }
    Add-Content $script:LogFile -Value ("--- change timeline (last $m min): " + $script:tl.Count + ' events viewed ---')
}

# ============================================================================================
#  ATTACK SURFACE: startup items, ports, risky services, firewall, sessions, IP blocks
#  Everything changed here is journaled (Snapshots > Undo) and never touches Microsoft core, scored,
#  remote-access or Datadog items.
# ============================================================================================
function Test-CanDisableService {
    param([string]$Name)
    if (Test-DatadogName $Name) { return 'Datadog is out of scope (rule 14)' }
    if ($script:NeverService -contains $Name) { return 'core, scored or remote-access service' }
    if ($script:RoleCfg[$script:Role].Services -contains $Name) { return 'this host''s scored service' }
    if ($script:RiskyServices -contains $Name) { return $null }
    $img = Get-RegRaw "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" 'ImagePath'
    if ((Get-ItemClass $img $Name) -eq 'microsoft') { return 'Microsoft service that is not on the safe-to-disable list' }
    return $null
}
function Disable-ServiceJournal {
    param([string]$Name)
    $why = Test-CanDisableService $Name
    if ($why) { Log "REFUSED to disable $Name : $why" 'ALERT'; return $false }
    $start = Get-SvcStart $Name
    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    $st = if ($s) { "$($s.Status)" } else { '' }
    try { if ($s -and $s.Status -eq 'Running') { Stop-Service -Name $Name -Force -ErrorAction Stop } } catch { Log "Could not stop $Name : $($_.Exception.Message)" 'WARN' }
    sc.exe config $Name start= disabled 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        [void](Add-Journal 'scstart' @{ name = $Name; oldStart = $start; oldState = $st })
        Log "Disabled service $Name (undo from Snapshots > Undo)" 'ACTION'; return $true
    }
    Log "Could not disable $Name (access denied?)" 'ALERT'; return $false
}

# ---------------- Startup & persistence review ----------------
function Get-StartupItems {
    $items = New-Object System.Collections.ArrayList
    function Add-StartItem {
        param($Kind, $Name, $Cmd, $Extra)
        [void]$items.Add([pscustomobject]@{ Kind = $Kind; Name = $Name; Cmd = $Cmd; Class = (Get-ItemClass $Cmd $Name); Extra = $Extra })
    }
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $rk = Get-Item $k
        foreach ($n in $rk.GetValueNames()) {
            if ($n -eq '') { continue }
            Add-StartItem 'runkey' $n ($rk.GetValue($n, $null, 'DoNotExpandEnvironmentNames')) @{ key = $k; kind = "$($rk.GetValueKind($n))" }
        }
    }
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $dirs += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    foreach ($d in $dirs) {
        if (Test-Path $d) {
            foreach ($f in Get-ChildItem $d -File -Force -ErrorAction SilentlyContinue) {
                if ($f.Name -ieq 'desktop.ini') { continue }
                Add-StartItem 'startfile' $f.Name $f.FullName @{ path = $f.FullName }
            }
        }
    }
    foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' }) {
        $acts = ($t.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' ; '
        Add-StartItem 'task' $t.TaskName $acts @{ path = $t.TaskPath; name = $t.TaskName; state = "$($t.State)" }
    }
    foreach ($s in Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' }) {
        if ($script:NeverService -contains $s.Name) { continue }
        Add-StartItem 'service' $s.Name $s.PathName @{ name = $s.Name }
    }
    return $items
}

function Invoke-StartupReview {
    param([switch]$ReportOnly)
    Log 'Collecting startup items (autoruns, startup folders, tasks, auto-start services)...'
    $all = @(Get-StartupItems)
    $hidden = @($all | Where-Object { $_.Class -in 'microsoft', 'protected' }).Count
    $cand = @($all | Where-Object { $_.Class -in 'SUSPECT', 'review' } | Sort-Object @{ Expression = { if ($_.Class -eq 'SUSPECT') { 0 } else { 1 } } }, Kind)
    if (-not $cand) { Log "Nothing to review ($hidden Microsoft/protected items hidden)." 'OK'; return }
    $i = 0
    foreach ($c in $cand) {
        $i++
        $col = if ($c.Class -eq 'SUSPECT') { 'Red' } else { 'Yellow' }
        Write-Host ('{0,3}) [{1,-7}] {2,-9} {3}' -f $i, $c.Class, $c.Kind, $c.Name) -ForegroundColor $col
        Write-Host ('            ' + $c.Cmd) -ForegroundColor DarkGray
    }
    Write-Host "($hidden Microsoft-signed or protected items are hidden. SUSPECT = unsigned, odd path, or a script host. review = signed by a third party.)"
    if ($ReportOnly) { return }
    Write-Host 'Disabling is reversible: autoruns are saved in the journal, files are moved to quarantine, tasks/services are only disabled.' -ForegroundColor Cyan
    $sel = Select-Indexes 'Numbers to disable (e.g. 1,3 or all; blank = none)' $cand.Count
    if (-not $sel) { return }
    Write-Host 'Plan:'; foreach ($n in $sel) { Write-Host ("  - {0} {1}" -f $cand[$n - 1].Kind, $cand[$n - 1].Name) }
    if (-not (Confirm-Yes 'Apply?')) { return }
    foreach ($n in $sel) {
        $c = $cand[$n - 1]
        try {
            switch ($c.Kind) {
                'runkey' {
                    [void](Add-Journal 'runkey' @{ key = $c.Extra.key; name = $c.Name; value = $c.Cmd; kind = $c.Extra.kind })
                    Remove-ItemProperty -Path $c.Extra.key -Name $c.Name -ErrorAction Stop
                    Log "Removed autorun $($c.Name) (saved for undo)" 'ACTION'
                }
                'startfile' {
                    $q = Join-Path "$script:Root\quarantine" ((Get-Date -Format 'HHmmss') + '_' + $c.Name)
                    Move-Item -LiteralPath $c.Extra.path -Destination $q -Force -ErrorAction Stop
                    [void](Add-Journal 'startfile' @{ orig = $c.Extra.path; quarantine = $q })
                    Log "Moved startup file $($c.Name) to quarantine" 'ACTION'
                }
                'task' {
                    Disable-ScheduledTask -TaskPath $c.Extra.path -TaskName $c.Extra.name -ErrorAction Stop | Out-Null
                    [void](Add-Journal 'task' @{ path = $c.Extra.path; name = $c.Extra.name })
                    Log "Disabled scheduled task $($c.Extra.path)$($c.Extra.name)" 'ACTION'
                }
                'service' { [void](Disable-ServiceJournal $c.Extra.name) }
            }
            $exe = Get-ExePath $c.Cmd
            if ($exe) {
                $running = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath -ieq $exe -and $_.ProcessId -ne $PID })
                foreach ($p in $running) {
                    if ($p.Name -match '(?i)^(svchost|lsass|services|wininit|System|csrss|winlogon)\.exe$') { continue }
                    if (Test-ProcProtected $p.ProcessId) { Log "Skipped $($p.Name) PID $($p.ProcessId): owned by whiteteam/blackteam or Datadog (out of scope)." 'WARN'; continue }
                    if (Confirm-YN "  $($p.Name) (PID $($p.ProcessId)) is still running from that file. Stop it?" $true) {
                        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue; Log "Stopped $($p.Name) PID $($p.ProcessId)" 'ACTION'
                    }
                }
            }
        } catch { Log "Failed on $($c.Name): $_" 'ALERT' }
    }
    Log 'Check Hermes. Undo anything from Snapshots > Undo.' 'WARN'
}

# ---------------- Listening ports review ----------------
function Invoke-PortReview {
    $cfg = $script:RoleCfg[$script:Role]
    $svcByPid = @{}
    foreach ($s in Get-CimInstance Win32_Service) { if ($s.ProcessId) { if (-not $svcByPid.ContainsKey([int]$s.ProcessId)) { $svcByPid[[int]$s.ProcessId] = @() }; $svcByPid[[int]$s.ProcessId] += $s.Name } }
    $procPath = @{}; foreach ($p in Get-CimInstance Win32_Process) { $procPath[[int]$p.ProcessId] = $p }
    $rows = @(); $seen = @{}
    foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort) {
        $key = "$($c.LocalPort)|$($c.OwningProcess)"; if ($seen[$key]) { continue }; $seen[$key] = $true
        $pr = $procPath[[int]$c.OwningProcess]
        $name = if ($pr) { $pr.Name } else { '?' }
        $sv = @($svcByPid[[int]$c.OwningProcess])
        $cls = if ($pr) { Get-ItemClass $pr.ExecutablePath $name } else { 'review' }
        if ($name -match '(?i)^(svchost|System|lsass|services|wininit)(\.exe)?$') { $cls = 'microsoft' }
        $exp = $cfg.Expected -contains [int]$c.LocalPort
        $verdict = if ($c.LocalPort -ge 49152) { 'dynamic' } elseif ($exp) { 'expected' } elseif ($cls -eq 'protected') { 'protected' } else { 'UNEXPECTED' }
        $rows += [pscustomobject]@{ Port = $c.LocalPort; Addr = $c.LocalAddress; PID = $c.OwningProcess; Process = $name; Services = ($sv -join ','); Class = $cls; Verdict = $verdict }
    }
    $i = 0
    foreach ($r in $rows) {
        $i++
        $col = switch ($r.Verdict) { 'UNEXPECTED' { 'Red' } 'dynamic' { 'DarkGray' } default { 'Gray' } }
        Write-Host ('{0,3}) {1,-5} {2,-15} {3,-22} {4,-26} {5,-9} {6}' -f $i, $r.Port, $r.Addr, $r.Process, $r.Services, $r.Class, $r.Verdict) -ForegroundColor $col
    }
    Write-Host "Expected for role '$($script:Role)': $($cfg.Expected -join ', ') (>= 49152 = dynamic RPC)" -ForegroundColor Cyan
    $sel = Select-Indexes 'Pick a number to act on (blank = none)' $rows.Count
    if ($sel.Count -ne 1) { return }
    $r = $rows[$sel[0] - 1]
    Write-Host "Port $($r.Port): $($r.Process) PID $($r.PID) services: $($r.Services)"
    Write-Host ' 1) Disable the owning service(s) (reversible)'
    Write-Host ' 2) Stop the process (not reversible; it may restart)'
    Write-Host ' 3) Block this port inbound in the firewall (reversible)'
    switch (Ask 'Select' '') {
        '1' {
            if (-not $r.Services) { Log 'This listener is not a service. Use option 2 or 3.' 'WARN'; return }
            foreach ($s in ($r.Services -split ',')) { if ($s) { [void](Disable-ServiceJournal $s) } }
        }
        '2' {
            if ($r.Process -match '(?i)^(svchost|System|lsass|services|wininit|csrss|winlogon)') { Log 'REFUSED: that is a core Windows process.' 'ALERT'; return }
            if (Test-DatadogName $r.Process) { Log 'REFUSED: Datadog is out of scope.' 'ALERT'; return }
            if (Test-ProcProtected ([int]$r.PID)) { Log 'REFUSED: that process belongs to whiteteam/blackteam or Datadog (out of scope).' 'ALERT'; return }
            if (Confirm-Yes "Stop $($r.Process) PID $($r.PID)?") { Stop-Process -Id $r.PID -Force -ErrorAction SilentlyContinue; Log "Stopped $($r.Process) PID $($r.PID)" 'ACTION' }
        }
        '3' {
            $prot = @(135, 139, 445, 3389, 5985, 5986, 47001) + @($cfg.Ports)
            if ($prot -contains [int]$r.Port) { Log "REFUSED: port $($r.Port) is a scored, remote-access or RPC/SMB port." 'ALERT'; return }
            if (Confirm-Yes "Block inbound TCP $($r.Port)?") {
                $nm = "BLUE-BLOCK-PORT-$($r.Port)"
                New-NetFirewallRule -Name $nm -DisplayName "BLUE-BLOCK port $($r.Port)" -Direction Inbound -Protocol TCP -LocalPort $r.Port -Action Block -Profile Any | Out-Null
                [void](Add-Journal 'fwblock' @{ name = $nm }); Log "Blocked inbound TCP $($r.Port)" 'ACTION'
            }
        }
    }
}

# ---------------- Risky services ----------------
function Invoke-RiskyServices {
    $rows = @()
    foreach ($n in $script:RiskyServices) {
        $s = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
        if ($s -and $s.StartMode -ne 'Disabled') { $rows += $s }
    }
    if (-not $rows) { Log 'None of the usual attack-surface services are enabled.' 'OK'; return }
    $i = 0; foreach ($s in $rows) { $i++; Write-Host ('{0,3}) {1,-18} {2,-9} {3,-8} {4}' -f $i, $s.Name, $s.StartMode, $s.State, $s.DisplayName) }
    Write-Host 'None of these are scored on your hosts. Spooler and RemoteRegistry are the classic abuse targets.'
    $sel = Select-Indexes 'Numbers to disable (blank = none)' $rows.Count
    foreach ($n in $sel) { [void](Disable-ServiceJournal $rows[$n - 1].Name) }
}

# ---------------- Firewall review ----------------
function Invoke-FirewallReview {
    $cfg = $script:RoleCfg[$script:Role]
    Show-Text (Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize)
    foreach ($p in Get-NetFirewallProfile) { if (-not $p.Enabled) { Log "Firewall profile $($p.Name) is OFF (Tamper > Registry watch can restore EnableFirewall; or: Set-NetFirewallProfile -Profile $($p.Name) -Enabled True)" 'ALERT' } }
    $pf = @{}; foreach ($f in Get-NetFirewallPortFilter -All) { $pf[$f.InstanceID] = $f }
    $af = @{}; foreach ($f in Get-NetFirewallApplicationFilter -All) { $af[$f.InstanceID] = $f }
    $rows = @()
    foreach ($r in Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow) {
        if ($r.DisplayName -like 'BLUE-BLOCK*' -or (Test-DatadogName $r.DisplayName) -or ($cfg.Rules -contains $r.Name)) { continue }
        $prog = "$($af[$r.Name].Program)"; $port = "$($pf[$r.Name].LocalPort)"; $proto = "$($pf[$r.Name].Protocol)"
        $why = $null
        if (-not $r.DisplayGroup -and -not $r.Group) { $why = 'custom rule (not part of a Windows feature group)' }
        if ($prog -match $script:SusPath -and $prog -notmatch $script:OkPath) { $why = 'program in a user-writable path' }
        if ($port -eq 'Any' -and $prog -in 'Any', '' -and $proto -in 'Any') { $why = 'allows ALL inbound traffic' }
        if ($why) { $rows += [pscustomobject]@{ Name = $r.Name; Display = $r.DisplayName; Program = $prog; Port = $port; Proto = $proto; Why = $why } }
    }
    if (-not $rows) { Log 'No suspicious inbound allow rules.' 'OK'; return }
    $i = 0; foreach ($r in $rows) { $i++; Write-Host ('{0,3}) {1}  [{2}/{3}]  {4}' -f $i, $r.Display, $r.Proto, $r.Port, $r.Why) -ForegroundColor Yellow; if ($r.Program -and $r.Program -ne 'Any') { Write-Host ('            ' + $r.Program) -ForegroundColor DarkGray } }
    $sel = Select-Indexes 'Numbers to DISABLE (reversible; blank = none)' $rows.Count
    foreach ($n in $sel) {
        $r = $rows[$n - 1]
        Disable-NetFirewallRule -Name $r.Name; [void](Add-Journal 'fwrule' @{ name = $r.Name }); Log "Disabled firewall rule: $($r.Display)" 'ACTION'
    }
}

# ---------------- Sessions and who is connected ----------------
function Invoke-Sessions {
    Write-Host '--- Interactive / RDP sessions ---'
    $q = quser 2>&1
    $q | ForEach-Object { Write-Host $_ }
    Write-Host '--- Remote peers on management ports (445, 3389, 5985) ---'
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -in 445, 3389, 5985, 5986 } |
        Group-Object LocalPort, RemoteAddress | Sort-Object Name | ForEach-Object { Write-Host ('  {0}  x{1}' -f $_.Name, $_.Count) }
    $id = Ask 'Session ID to log off (blank = none)'
    if ($id -match '^\d+$') {
        $owner = $null
        foreach ($l in @($q)) {
            $tok = (([string]$l) -replace '^[> ]', '') -split '\s+' | Where-Object { $_ }
            if ($tok.Count -ge 3 -and (($tok[1] -eq $id) -or ($tok[2] -eq $id))) { $owner = $tok[0] }
        }
        if (-not $owner) { Log "Could not match session $id to a user, so nothing was logged off." 'WARN'; return }
        if (Test-Protected $owner) { Log "REFUSED: session $id belongs to $owner, which is out of scope (rule 6)." 'ALERT'; return }
        if (Confirm-Yes "Log off session $id ($owner)?") { logoff $id; Log "Logged off session $id ($owner)" 'ACTION' }
    }
}

# ---------------- Block / unblock single IPs ----------------
function Get-DatadogRanges {
    $cache = Join-Path $script:Root 'datadog-ranges.txt'
    if (Test-Path $cache) { return (Get-Content $cache) }
    try {
        $j = Invoke-RestMethod -Uri 'https://ip-ranges.us5.datadoghq.com/' -TimeoutSec 15 -ErrorAction Stop
        $all = foreach ($p in $j.PSObject.Properties) { if ($p.Value -and $p.Value.PSObject.Properties['prefixes_ipv4']) { $p.Value.prefixes_ipv4 } }
        $all = @($all | Sort-Object -Unique)
        if ($all) { $all | Out-File $cache -Encoding ascii; return $all }
    } catch { }
    return $null
}
function Invoke-BlockIp {
    Write-Host ' 1) Block an IP   2) Unblock an IP   3) List blocks'
    $m = Ask 'Select' '1'
    if ($m -eq '3') {
        Get-NetFirewallRule -DisplayName 'BLUE-BLOCK*' -ErrorAction SilentlyContinue | ForEach-Object { '{0}  {1}  remote={2}' -f $_.DisplayName, $_.Direction, ($_ | Get-NetFirewallAddressFilter).RemoteAddress }
        return
    }
    $addr = Ask 'Single IPv4 address'
    $parsed = $null
    if (-not $addr -or $addr -match '[/\-,*]' -or -not [Net.IPAddress]::TryParse($addr, [ref]$parsed) -or $parsed.AddressFamily -ne 'InterNetwork') { Log "REFUSED: give one plain IPv4 address (no subnets/ranges, rule 15)." 'ALERT'; return }
    if ($m -eq '2') {
        foreach ($n in "BLUE-BLOCK-$addr-in", "BLUE-BLOCK-$addr-out") { Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue }
        Log "Removed block for $addr" 'ACTION'; return
    }
    if ($addr -match '^127\.') { Log 'REFUSED: loopback.' 'ALERT'; return }
    if (Test-IpInCidr $addr '172.16.1.0/24') { Log 'REFUSED: management network is out of scope (rule 14).' 'ALERT'; return }
    if ($addr -match '^10\.\d+\.1\.99$') { Log 'REFUSED: NetBird egress is out of scope (rule 14).' 'ALERT'; return }
    $dd = Get-DatadogRanges
    if ($dd) { foreach ($c in $dd) { if (Test-IpInCidr $addr $c) { Log 'REFUSED: Datadog published range (rule 14).' 'ALERT'; return } } }
    $team = Get-TeamNumber; $force = $false
    $soft = $null
    if ($team -and (Test-IpInCidr $addr "10.$team.1.0/24")) { $soft = 'inside your own LAN' }
    elseif ($team -and (Test-IpInCidr $addr "192.168.$team.0/24")) { $soft = 'inside your own cloud subnet' }
    elseif (Test-IpInCidr $addr '172.20.0.0/16') { $soft = 'in 172.20.x.x (barrier/scoring side: blocking may fail uptime checks)' }
    elseif (-not ($addr -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') -and -not $dd) { $soft = 'a public IP and the Datadog list could not be loaded to verify it' }
    if ($soft) { if (-not (Confirm-Yes "$addr is $soft. Block anyway?")) { return } }
    foreach ($d in @(@('in', 'Inbound'), @('out', 'Outbound'))) {
        $nm = "BLUE-BLOCK-$addr-$($d[0])"
        if (-not (Get-NetFirewallRule -Name $nm -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name $nm -DisplayName "BLUE-BLOCK $addr $($d[1])" -Direction $d[1] -Action Block -RemoteAddress $addr -Profile Any | Out-Null
            [void](Add-Journal 'fwblock' @{ name = $nm })
        }
    }
    Log "Blocked $addr in and out. Existing sessions stay open: log them off (Sessions), close SMB sessions, or kill the shell." 'ACTION'
}

# ============================================================================================
#  CONFIG SNAPSHOTS + RESTORE (not a VM snapshot: the packet says there are no VM reverts)
#  Captures settings that commonly get broken: services, tasks, autoruns, firewall, hosts, users, shares,
#  IIS config + web root, WinRM settings, watched registry values. Restore is per component with a plan + confirm,
#  and a "pre-restore" snapshot is taken first so you can go back again.
#  Optional: a Windows restore point on Windows 10/11 (not available on Server).
# ============================================================================================
function Get-ScModeFromName { param([string]$n) switch ($n) { 'Auto' { 'auto' } 'Manual' { 'demand' } 'Disabled' { 'disabled' } 'Boot' { 'boot' } 'System' { 'system' } default { 'demand' } } }
function Find-Appcmd { $a = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'; if (Test-Path $a) { return $a }; return $null }

function New-ConfigSnapshot {
    param([string]$Label, [switch]$NoPrompt)
    if (-not $Label) { $Label = Ask 'Snapshot name' ('snap-' + (Get-Date -Format 'HHmm')) }
    $Label = $Label -replace '[^\w\-\.]', '_'
    $dir = Join-Path "$script:Root\snap" $Label
    if (Test-Path $dir) {
        if ($NoPrompt -or -not (Confirm-YN "Snapshot '$Label' already exists. Overwrite it?" $false)) { if ($NoPrompt) { $dir = $dir + '-' + (Get-Date -Format 'HHmmss') } else { return } }
        else { Remove-Item $dir -Recurse -Force }
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $done = @()
    Log "Creating config snapshot '$Label'..."

    try { Get-CimInstance Win32_Service | Select-Object Name, StartMode, State | Export-Csv "$dir\services.csv" -NoTypeInformation -Encoding ASCII; $done += 'services' } catch { Log "services: $_" 'WARN' }
    try {
        $td = "$dir\tasks"; New-Item -ItemType Directory $td -Force | Out-Null; $rows = @()
        foreach ($t in Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
            $f = (($t.TaskPath + $t.TaskName) -replace '[\\/:*?"<>|]', '_') + '.xml'
            Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File (Join-Path $td $f) -Encoding unicode
            $rows += [pscustomobject]@{ Path = $t.TaskPath; Name = $t.TaskName; State = "$($t.State)"; File = $f }
        }
        $rows | Export-Csv "$dir\tasks.csv" -NoTypeInformation -Encoding ASCII; $done += 'tasks'
    } catch { Log "tasks: $_" 'WARN' }
    try {
        $regs = @{ 'run-hklm' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; 'run-wow' = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
                   'run-hkcu' = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; 'runonce-hklm' = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
        foreach ($k in $regs.Keys) { reg export $regs[$k] "$dir\$k.reg" /y 2>&1 | Out-Null }
        $done += 'autoruns'
    } catch { Log "autoruns: $_" 'WARN' }
    try { netsh advfirewall export "$dir\firewall.wfw" 2>&1 | Out-Null; $done += 'firewall' } catch { Log "firewall: $_" 'WARN' }
    try { Copy-Item "$env:windir\System32\drivers\etc\hosts" "$dir\hosts" -Force; $done += 'hosts' } catch { }
    try {
        Get-LocalUser | Select-Object Name, Enabled | Export-Csv "$dir\users.csv" -NoTypeInformation -Encoding ASCII
        (Get-AdminNames) | Out-File "$dir\admins.txt" -Encoding ascii; $done += 'users'
    } catch { Log "users: $_" 'WARN' }
    try {
        $sh = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special } | ForEach-Object {
            $s = $_
            @{ Name = $s.Name; Path = $s.Path; Description = $s.Description
               Access = @(Get-SmbShareAccess -Name $s.Name | ForEach-Object { @{ Account = $_.AccountName; Right = "$($_.AccessRight)"; Type = "$($_.AccessControlType)" } }) }
        })
        ConvertTo-Json -InputObject $sh -Depth 5 | Set-Content "$dir\shares.json" -Encoding ASCII; $done += 'shares'
    } catch { }
    $appcmd = Find-Appcmd
    if ($appcmd -and (Get-Service W3SVC -ErrorAction SilentlyContinue)) {
        try {
            & $appcmd add backup "blue-$Label" 2>&1 | Out-Null
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            foreach ($site in Get-Website) {
                $p = [Environment]::ExpandEnvironmentVariables($site.PhysicalPath)
                if (Test-Path $p) { robocopy $p "$dir\wwwroot\$($site.Name)" /MIR /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null }
            }
            $done += 'iis'
        } catch { Log "iis: $_" 'WARN' }
    }
    try {
        $w = @{}
        foreach ($n in 'Basic', 'Kerberos', 'Negotiate', 'Certificate', 'CredSSP') { $w["Auth\$n"] = (Get-Item "WSMan:\localhost\Service\Auth\$n" -ErrorAction Stop).Value }
        $w['AllowUnencrypted'] = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction Stop).Value
        $w['IPv4Filter'] = (Get-Item WSMan:\localhost\Service\IPv4Filter -ErrorAction Stop).Value
        $w | ConvertTo-Json | Set-Content "$dir\winrm.json" -Encoding ASCII; $done += 'winrm'
    } catch { }
    try {
        $h = [ordered]@{}
        foreach ($wi in $script:RegWatch) { $v = Get-RegRaw $wi.P $wi.N; $h[($wi.P + '|' + $wi.N)] = $(if ($null -eq $v) { '<absent>' } else { $v }) }
        $h | ConvertTo-Json | Set-Content "$dir\regvals.json" -Encoding ASCII; $done += 'regvals'
    } catch { }
    secedit /export /cfg "$dir\secpol.inf" /quiet 2>&1 | Out-Null

    if (-not $NoPrompt -and (Get-CimInstance Win32_OperatingSystem).ProductType -eq 1) {
        Write-Host 'This is a Windows client OS, so a Windows restore point is possible (a deeper rollback via System Restore).' -ForegroundColor Cyan
        Write-Host 'The packet says "no reverts" about the competition store; a local restore point is not mentioned. If unsure, ask White Team first.' -ForegroundColor Yellow
        if (Confirm-YN 'Create a Windows restore point too?' $false) {
            try {
                Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
                Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord -ErrorAction SilentlyContinue
                Checkpoint-Computer -Description "BlueOps $Label" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
                $done += 'restorepoint'; Log 'Restore point created.' 'ACTION'
            } catch { Log "Restore point failed: $_" 'WARN' }
        }
    }
    @{ label = $Label; time = (Get-Date -Format s); host = $env:COMPUTERNAME; components = $done } | ConvertTo-Json | Set-Content "$dir\meta.json" -Encoding ASCII
    Log ("Snapshot '{0}' saved: {1}" -f $Label, ($done -join ', ')) 'OK'
}

function Get-Snapshots {
    $out = @()
    foreach ($d in Get-ChildItem "$script:Root\snap" -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime) {
        $mf = Join-Path $d.FullName 'meta.json'
        if (Test-Path $mf) { $m = Get-Content $mf -Raw | ConvertFrom-Json; $out += [pscustomobject]@{ Label = $d.Name; Time = $m.time; Components = @($m.components); Dir = $d.FullName } }
    }
    return $out
}
function Show-Snapshots {
    $s = @(Get-Snapshots)
    if (-not $s) { Write-Host 'No snapshots yet.'; return }
    $i = 0; foreach ($x in $s) { $i++; Write-Host ('{0,3}) {1,-28} {2}   [{3}]' -f $i, $x.Label, $x.Time, ($x.Components -join ',')) }
}

function Restore-ConfigSnapshot {
    $s = @(Get-Snapshots)
    if (-not $s) { Write-Host 'No snapshots yet.'; return }
    Show-Snapshots
    $p = Select-Indexes 'Restore from which snapshot' $s.Count
    if ($p.Count -ne 1) { return }
    $snap = $s[$p[0] - 1]; $dir = $snap.Dir
    $comps = @($snap.Components | Where-Object { $_ -ne 'restorepoint' })
    $i = 0; foreach ($c in $comps) { $i++; Write-Host ("  {0}) {1}" -f $i, $c) }
    Write-Host '  (users restores enabled/disabled state and admin membership but never passwords: the vault has those)'
    $sel = Select-Indexes 'Components to restore (e.g. 1,2 or all)' $comps.Count
    if (-not $sel) { return }
    New-ConfigSnapshot -Label ('pre-restore-' + (Get-Date -Format 'HHmmss')) -NoPrompt
    foreach ($n in $sel) {
        $c = $comps[$n - 1]
        Write-Host "--- restoring $c ---" -ForegroundColor Cyan
        try {
            switch ($c) {
                'services' {
                    $cur = @{}; foreach ($x in Get-CimInstance Win32_Service) { $cur[$x.Name] = $x }
                    $diff = @(foreach ($x in Import-Csv "$dir\services.csv") {
                        if (Test-DatadogName $x.Name) { continue }
                        $cv = $cur[$x.Name]; if (-not $cv) { continue }
                        if ($cv.StartMode -ne $x.StartMode -or ($x.State -eq 'Running' -and $cv.State -ne 'Running')) { [pscustomobject]@{ Name = $x.Name; Now = "$($cv.StartMode)/$($cv.State)"; Was = "$($x.StartMode)/$($x.State)"; Mode = $x.StartMode; State = $x.State } }
                    })
                    if (-not $diff) { Log 'Services already match the snapshot.' 'OK'; continue }
                    Show-Text ($diff | Format-Table Name, Now, Was -AutoSize)
                    if (Confirm-Yes "Set these $($diff.Count) services back to the snapshot state?") {
                        foreach ($d in $diff) {
                            sc.exe config $d.Name start= (Get-ScModeFromName $d.Mode) 2>&1 | Out-Null
                            if ($d.State -eq 'Running') { Start-Service -Name $d.Name -ErrorAction SilentlyContinue }
                            Log "Restored service $($d.Name) -> $($d.Was)" 'ACTION'
                        }
                    }
                }
                'tasks' {
                    foreach ($t in Import-Csv "$dir\tasks.csv") {
                        $ex = Get-ScheduledTask -TaskName $t.Name -TaskPath $t.Path -ErrorAction SilentlyContinue
                        if (-not $ex) {
                            if (Confirm-YN "Task $($t.Path)$($t.Name) is missing. Re-register it from the snapshot?" $true) {
                                Register-ScheduledTask -Xml (Get-Content (Join-Path "$dir\tasks" $t.File) -Raw) -TaskName $t.Name -TaskPath $t.Path -Force -ErrorAction Stop | Out-Null
                                Log "Re-registered task $($t.Name)" 'ACTION'
                            }
                        } elseif ("$($ex.State)" -ne $t.State -and (Confirm-YN "Task $($t.Name) is $($ex.State) but was $($t.State). Fix?" $true)) {
                            if ($t.State -eq 'Disabled') { Disable-ScheduledTask -TaskName $t.Name -TaskPath $t.Path | Out-Null } else { Enable-ScheduledTask -TaskName $t.Name -TaskPath $t.Path | Out-Null }
                            Log "Task $($t.Name) state restored" 'ACTION'
                        }
                    }
                    Write-Host '(New tasks that were not in the snapshot are handled by Attack surface > Startup review.)'
                }
                'autoruns' {
                    if (Confirm-Yes 'Re-import the saved Run keys? (adds back missing/changed values; does not delete new ones)') {
                        foreach ($f in Get-ChildItem "$dir\*.reg") { reg import $f.FullName 2>&1 | Out-Null }
                        Log 'Run keys re-imported.' 'ACTION'
                    }
                }
                'firewall' {
                    if (Confirm-Yes 'REPLACE the whole Windows Firewall policy with the snapshot (a pre-restore copy was just saved)?') { netsh advfirewall import "$dir\firewall.wfw" 2>&1 | Out-Null; Log 'Firewall policy restored.' 'ACTION' }
                }
                'hosts' { if (Confirm-Yes 'Replace the hosts file with the snapshot copy?') { Copy-Item "$dir\hosts" "$env:windir\System32\drivers\etc\hosts" -Force; Log 'hosts restored.' 'ACTION' } }
                'users' {
                    foreach ($u in Import-Csv "$dir\users.csv") {
                        if (Test-Protected $u.Name) { continue }
                        $cu = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue
                        if (-not $cu) { Log "Account $($u.Name) existed in the snapshot but is gone now (recreate by hand if needed)." 'WARN'; continue }
                        $want = ($u.Enabled -eq 'True')
                        if ($cu.Enabled -ne $want) { if ($want) { Enable-LocalUser $u.Name } else { Disable-LocalUser $u.Name }; Log "Account $($u.Name) enabled=$want restored" 'ACTION' }
                    }
                    $nowAdm = Get-AdminNames
                    foreach ($a in Get-Content "$dir\admins.txt") { if ($a -and ($nowAdm -notcontains $a)) { try { Add-LocalGroupMember -Group Administrators -Member $a -ErrorAction Stop; Log "Re-added $a to Administrators" 'ACTION' } catch { Log "Could not re-add $a : $_" 'WARN' } } }
                    foreach ($a in $nowAdm) { if ((Get-Content "$dir\admins.txt") -notcontains $a) { Log "Now an admin but was not in the snapshot: $a (remove via Accounts if unwanted)" 'WARN' } }
                }
                'shares' {
                    $saved = Get-Content "$dir\shares.json" -Raw | ConvertFrom-Json
                    $have = @((Get-SmbShare).Name)
                    foreach ($s in @($saved)) {
                        if ($have -notcontains $s.Name) {
                            if (Confirm-YN "Share '$($s.Name)' ($($s.Path)) is missing. Recreate it?" $true) {
                                New-SmbShare -Name $s.Name -Path $s.Path -Description $s.Description | Out-Null; $have += $s.Name; Log "Recreated share $($s.Name)" 'ACTION'
                            } else { continue }
                        }
                        $want = @($s.Access)
                        foreach ($a in $want) {
                            $r = switch ($a.Right) { 'Full' { 'Full' } 'Change' { 'Change' } default { 'Read' } }
                            if ($a.Type -eq 'Deny') { Block-SmbShareAccess -Name $s.Name -AccountName $a.Account -Force -ErrorAction SilentlyContinue | Out-Null }
                            else { Grant-SmbShareAccess -Name $s.Name -AccountName $a.Account -AccessRight $r -Force -ErrorAction SilentlyContinue | Out-Null }
                        }
                        foreach ($cur in Get-SmbShareAccess -Name $s.Name) { if (-not ($want | Where-Object { $_.Account -eq $cur.AccountName })) { Revoke-SmbShareAccess -Name $s.Name -AccountName $cur.AccountName -Force -ErrorAction SilentlyContinue | Out-Null; Log "Removed extra share permission $($cur.AccountName) on $($s.Name)" 'ACTION' } }
                    }
                }
                'iis' {
                    $appcmd = Find-Appcmd
                    if ($appcmd -and (Confirm-Yes 'Restore IIS configuration from the snapshot backup AND mirror the web root back (deletes files not in the snapshot)?')) {
                        & $appcmd restore backup "blue-$($snap.Label)" 2>&1 | Out-Null
                        Import-Module WebAdministration -ErrorAction SilentlyContinue
                        foreach ($site in Get-Website) {
                            $p = [Environment]::ExpandEnvironmentVariables($site.PhysicalPath); $src = "$dir\wwwroot\$($site.Name)"
                            if ((Test-Path $src) -and $p) { robocopy $src $p /MIR /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null }
                        }
                        Log 'IIS config and web root restored.' 'ACTION'
                    }
                }
                'winrm' {
                    $w = Get-Content "$dir\winrm.json" -Raw | ConvertFrom-Json
                    foreach ($pr in $w.PSObject.Properties) {
                        $path = "WSMan:\localhost\Service\$($pr.Name)"
                        $cur = (Get-Item $path -ErrorAction SilentlyContinue).Value
                        if ("$cur" -ne "$($pr.Value)") {
                            if ($pr.Name -eq 'IPv4Filter') { Set-Item $path -Value $pr.Value -ErrorAction SilentlyContinue }
                            else { Set-Item $path -Value ($pr.Value -eq 'true') -ErrorAction SilentlyContinue }
                            Log "WinRM $($pr.Name): $cur -> $($pr.Value)" 'ACTION'
                        }
                    }
                }
                'regvals' {
                    $saved = Get-Content "$dir\regvals.json" -Raw | ConvertFrom-Json
                    foreach ($wi in $script:RegWatch) {
                        if ($wi.K -eq 'Multi') { continue }
                        $sv = $saved.PSObject.Properties[($wi.P + '|' + $wi.N)].Value
                        $cv = Get-RegRaw $wi.P $wi.N; $cvs = if ($null -eq $cv) { '<absent>' } else { $cv }
                        if ($sv -ne $cvs) {
                            if ($sv -eq '<absent>') { Remove-RegJournal $wi.P $wi.N } else { Set-RegJournal $wi.P $wi.N $(if ($wi.K -eq 'DWord') { [int]$sv } else { $sv }) $wi.K }
                            Log "Registry $($wi.P)\$($wi.N): $cvs -> $sv" 'ACTION'
                        }
                    }
                }
            }
        } catch { Log "Restore of $c failed: $_" 'ALERT' }
    }
    Log 'Restore finished. Re-check Hermes.' 'WARN'
}

function Invoke-UndoMenu {
    $entries = @(Get-JournalEntries | Where-Object { -not $_.undone })
    if (-not $entries) { Write-Host 'Nothing to undo: the journal has no open entries.'; return }
    $i = 0; foreach ($e in $entries) { $i++; Write-Host ('{0,3}) #{1,-4} {2}  {3}' -f $i, $e.id, $e.time, (Format-JournalEntry $e)) }
    Write-Host '  Type numbers to undo (e.g. 3 or 1-4 or all); newest first is safest.'
    $sel = Select-Indexes 'Undo which' $entries.Count
    foreach ($n in @($sel | Sort-Object -Descending)) { [void](Undo-JournalEntry $entries[$n - 1]) }
}

# ============================================================================================
#  SITUATION TOOLS: hunt, logons, evidence, incident notes, status
# ============================================================================================
# ---------------- Screen-watcher / keylogger / remote-control hunt (report only, changes nothing) ----------------
function Invoke-SpyHunt {
    $script:SpyN = 0
    function SpyFlag { param([string]$m) $script:SpyN++; Log $m 'ALERT' }
    $tools = '(?i)anydesk|teamviewer|tv_w32|tv_x64|ultravnc|uvnc|winvnc|tightvnc|tvnserver|realvnc|vncserver|vncviewer|rustdesk|screenconnect|connectwise|splashtop|ammyy|radmin|logmein|meshagent|meshcentral|remoteutilities|rutserv|rfusclient|netsupport|client32|dameware|supremo|aeroadmin|zoho ?assist|getscreen|ngrok|chisel|frpc|plink|putty|(^|[\\ ])nc\.exe|ncat|socat|cobalt|beacon|meterpreter|empire|sliver|havoc|mythic|keylog|klog|screenshot|screencap|screengrab|spyware|spy\.exe|(^|[\\ ])rat\.exe|stealer'
    $okTool = '(?i)datadog|dd-agent|netbird|wazuh'
    Write-Host '--- Processes and services that look like remote control / screen capture / keyloggers ---'
    foreach ($p in (Get-CimInstance Win32_Process)) {
        $t = "{0} {1} {2}" -f $p.Name, $p.ExecutablePath, $p.CommandLine
        if (($t -match $tools) -and ($t -notmatch $okTool) -and $p.ProcessId -ne $PID -and $t -notmatch 'BlueMenu') { SpyFlag ("[REVIEW] process: {0} (PID {1}) {2}" -f $p.Name, $p.ProcessId, $p.ExecutablePath) }
    }
    foreach ($s in (Get-CimInstance Win32_Service)) {
        $t = "{0} {1} {2}" -f $s.Name, $s.DisplayName, $s.PathName
        if (($t -match $tools) -and ($t -notmatch $okTool)) { SpyFlag ("[REVIEW] service: {0} ({1}, {2}) {3}" -f $s.Name, $s.State, $s.StartMode, $s.PathName) }
    }
    Write-Host '--- Installed programs that look like remote control tools ---'
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        foreach ($a in (Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
            if ($a.DisplayName -and ($a.DisplayName -match $tools) -and ($a.DisplayName -notmatch $okTool)) { SpyFlag ("[REVIEW] installed: {0} {1}" -f $a.DisplayName, $a.DisplayVersion) }
        }
    }
    Write-Host '--- Listening ports used by common remote-control tools ---'
    $odd = 5500, 5800, 5900, 5901, 5902, 5903, 5938, 7070, 8040, 8041, 21115, 21116, 21117, 21118, 21119, 4444, 1337, 31337
    foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        if ($odd -contains [int]$c.LocalPort) {
            $pn = (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            if ($pn -and (Test-DatadogName $pn)) { continue }
            SpyFlag ("[REVIEW] listening on {0}:{1} by {2} (PID {3})" -f $c.LocalAddress, $c.LocalPort, $pn, $c.OwningProcess)
        }
    }
    Write-Host '--- Who else is logged on (a console or RDP session you did not start) ---'
    $q = @(quser 2>&1)
    foreach ($l in $q) { Write-Host ('  ' + $l) }
    Log 'Compare the sessions above with your team. An unknown user, or a Disconnected session you did not start, is worth reviewing.' 'INFO'
    Write-Host '--- Settings that allow someone to watch or control a session ---'
    $shadow = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue).Shadow
    if ($null -ne $shadow) { SpyFlag ("RDP shadowing policy is set (Shadow={0}): lets an admin view or control another session." -f $shadow) }
    $ra = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue).fAllowToGetHelp
    if ($ra -eq 1) { SpyFlag 'Remote Assistance is enabled (fAllowToGetHelp=1).' }
    $aw = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue
    if ($aw.AppInit_DLLs) { SpyFlag ("AppInit_DLLs is set: {0} (a DLL loaded into every program, common keylogger spot; LoadAppInit_DLLs={1})" -f $aw.AppInit_DLLs, $aw.LoadAppInit_DLLs) }
    $kb = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E96B-E325-11CE-B91E-002BE10318FC}'
    $kp = Get-ItemProperty $kb -ErrorAction SilentlyContinue
    foreach ($nm in 'UpperFilters', 'LowerFilters') {
        $v = @($kp.$nm | Where-Object { $_ -and $_ -ne 'kbdclass' })
        if ($v.Count -gt 0) { SpyFlag ("Keyboard class {0} has extra driver(s): {1} (a keyboard filter driver can log every key)" -f $nm, ($v -join ', ')) }
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*') {
        foreach ($a in (Get-ItemProperty $k -ErrorAction SilentlyContinue)) { if ($a.Debugger) { SpyFlag ("Image File Execution Options debugger on {0}: {1}" -f $a.PSChildName, $a.Debugger) } }
    }
    Write-Host '--- Non-Microsoft drivers loaded that could capture input ---'
    foreach ($d in (Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName })) {
        $path = ($d.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot', $env:windir -replace '"', '')
        if ($path -match '(?i)\\system32\\drivers\\' -or $path -match '(?i)\\windows\\') { continue }
        if (Test-DatadogName "$($d.Name) $path") { continue }
        SpyFlag ("[REVIEW] driver outside the Windows folder: {0} {1}" -f $d.Name, $path)
    }
    if ($script:SpyN -eq 0) { Log 'Nothing obvious found. A quiet result does not prove the machine is clean: custom malware may not match these names.' 'OK' }
    else { Log "$($script:SpyN) item(s) to review. This check only reports. To stop one: Risky services (services), Ports (processes), Startup review (autostarts). Check each is not scored or needed first." 'WARN' }
}

function Invoke-Hunt {
    $mins = [int](Ask 'Look-back window in minutes for recent files' '120')
    $n = 0
    function Flag { param([string]$m) $script:HuntN++; Log $m 'ALERT' }
    $script:HuntN = 0
    Write-Host '--- Processes ---'
    $procs = Get-CimInstance Win32_Process; $byId = @{}; foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }
    foreach ($p in $procs) {
        if (Test-DatadogName ("{0} {1} {2}" -f $p.Name, $p.ExecutablePath, $p.CommandLine)) { continue }
        if ($p.ExecutablePath -and $p.ExecutablePath -match $script:SusPath -and $p.ExecutablePath -notmatch $script:OkPath) { Flag ("[REVIEW] process in user-writable path: {0} (PID {1}) {2}" -f $p.Name, $p.ProcessId, $p.ExecutablePath) }
        if ($p.CommandLine -and $p.CommandLine -match $script:BadCmd -and $p.ProcessId -ne $PID -and $p.CommandLine -notmatch 'BlueMenu') { Flag ("Suspicious command line: {0} (PID {1}): {2}" -f $p.Name, $p.ProcessId, $p.CommandLine) }
        $par = $byId[[int]$p.ParentProcessId]
        if ($par -and $par.Name -match '(?i)^(w3wp|sqlservr|httpd|java|tomcat\d*|wsmprovhost|winrmhost)\.exe$' -and $p.Name -match '(?i)^(cmd|powershell|pwsh|wscript|cscript|whoami|net|net1|certutil|bitsadmin|mshta|rundll32|regsvr32)\.exe$') { Flag ("Service process spawned a shell/tool: {0} -> {1} (PID {2}) {3}" -f $par.Name, $p.Name, $p.ProcessId, $p.CommandLine) }
    }
    Write-Host '--- Established connections (non-loopback) ---'
    $est = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } | ForEach-Object {
        $pn = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        [pscustomobject]@{ Process = $pn; PID = $_.OwningProcess; Local = "$($_.LocalAddress):$($_.LocalPort)"; Remote = "$($_.RemoteAddress):$($_.RemotePort)" } } | Where-Object { -not (Test-DatadogName $_.Process) })
    Show-Text ($est | Sort-Object Process | Format-Table -AutoSize)
    foreach ($c in $est) { if ($c.Process -match '(?i)^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil)$') { Flag ("Shell/LOLBin with a network connection: {0} PID {1} -> {2}" -f $c.Process, $c.PID, $c.Remote) } }
    Write-Host "--- Executable/script files modified in the last $mins min ---"
    $since = (Get-Date).AddMinutes(-$mins)
    $roots = @("$env:windir\Temp", "$env:ProgramData", 'C:\Users\Public', 'C:\Users\*\Desktop', 'C:\Users\*\Downloads', 'C:\Users\*\AppData\Local\Temp', 'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu')
    $exts = '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr', '.sys', '.aspx', '.asp', '.ashx', '.php', '.jsp', '.lnk', '.msi'
    Get-ChildItem -Path $roots -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since -and ($exts -contains $_.Extension.ToLower()) -and -not (Test-DatadogName $_.FullName) -and $_.FullName -notlike "$script:Root*" } |
        ForEach-Object { Flag ("[REVIEW] recent file: {0}  ({1})" -f $_.FullName, $_.LastWriteTime) }
    Get-ChildItem "$env:windir\System32\Tasks" -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $since -and -not (Test-DatadogName $_.FullName) } | ForEach-Object { Flag ("Scheduled task file changed: {0}  ({1})" -f $_.FullName, $_.LastWriteTime) }
    Write-Host '--- Accessibility-binary backdoors ---'
    $ref = @{}; foreach ($r in "$env:windir\System32\cmd.exe", "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe") { if (Test-Path $r) { $ref[(Get-FileHash $r).Hash] = $r } }
    foreach ($f in 'sethc', 'utilman', 'osk', 'narrator', 'magnify', 'displayswitch') {
        $p = "$env:windir\System32\$f.exe"; if (-not (Test-Path $p)) { continue }
        if ($ref.ContainsKey((Get-FileHash $p).Hash)) { Flag ("BACKDOOR: $p is a copy of " + $ref[(Get-FileHash $p).Hash]) }
        $sg = Get-AuthenticodeSignature $p; if ($sg.Status -ne 'Valid') { Flag "$p signature status is $($sg.Status)" }
    }
    Write-Host '--- WMI event subscriptions (persistence) ---'
    foreach ($c in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
        Get-CimInstance -Namespace 'root\subscription' -ClassName $c -ErrorAction SilentlyContinue | Where-Object { ($_ | Out-String) -notmatch 'SCM Event Log' } | ForEach-Object { Flag ("WMI {0}: {1}" -f $c, ((($_ | Out-String).Trim()) -replace '\s+', ' ')) }
    }
    Log ("Hunt complete. Flagged: {0}. Next: Attack surface > Startup review, Tamper > Service audit." -f $script:HuntN) 'OK'
}

function Invoke-Logons {
    $mins = [int](Ask 'Look back how many minutes' '120'); $start = (Get-Date).AddMinutes(-$mins)
    Write-Host '--- Remote logons (4624 type 3/10) ---'
    $rows = foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $start } -ErrorAction SilentlyContinue) {
        $d = Get-EvData $e
        if ($d.LogonType -in '3', '10' -and $d.IpAddress -and $d.IpAddress -notin '-', '::1', '127.0.0.1' -and $d.TargetUserName -notmatch '\$$') { [pscustomobject]@{ User = $d.TargetUserName; Type = $d.LogonType; From = $d.IpAddress } }
    }
    if ($rows) { $rows | Group-Object User, Type, From | Sort-Object Count -Descending | ForEach-Object { '{0,5} x  {1}' -f $_.Count, $_.Name } | Out-String | Write-Host } else { Write-Host '  none (or logon auditing is off: Setup > Visibility)' }
    Write-Host '--- Failed logons (4625) by source ---'
    $fr = foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $start } -ErrorAction SilentlyContinue) { $d = Get-EvData $e; [pscustomobject]@{ User = $d.TargetUserName; From = $d.IpAddress } }
    if ($fr) { $fr | Group-Object From, User | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object { '{0,5} x  {1}' -f $_.Count, $_.Name } | Out-String | Write-Host }
    Write-Host '--- Account / group / task / service changes ---'
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4697, 4698, 4702; StartTime = $start } -ErrorAction SilentlyContinue) {
        $d = Get-EvData $e; Log ("{0} id={1} target={2} by={3} {4}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $d.TargetUserName, $d.SubjectUserName, $d.MemberName) 'WARN'
    }
    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $start } -ErrorAction SilentlyContinue) {
        $d = Get-EvData $e; if (-not (Test-DatadogName ($d.ServiceName + $d.ImagePath))) { Log ("{0} NEW SERVICE {1}: {2}" -f $e.TimeCreated.ToString('HH:mm:ss'), $d.ServiceName, $d.ImagePath) 'ALERT' }
    }
}

function Invoke-Evidence {
    $f = Join-Path "$script:Root\evidence" ("evidence-$env:COMPUTERNAME-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    & {
        "Evidence bundle $(Get-Date)  host=$env:COMPUTERNAME  user=$env:USERNAME"
        '--- whoami /all'; whoami /all
        '--- ipconfig'; ipconfig /all
        '--- netstat'; netstat -ano
        '--- processes'; Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | Format-List | Out-String -Width 250
        '--- sessions'; quser 2>&1
        '--- local users'; net user; '--- admins'; net localgroup Administrators
        '--- services (non-running auto)'; Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | Select-Object Name, State, PathName | Format-Table -AutoSize | Out-String -Width 250
        '--- journal'; if (Test-Path $script:Journal) { Get-Content $script:Journal }
        '--- blue.log (last 200)'; Get-Content $script:LogFile -Tail 200
        '--- incidents'; if (Test-Path "$script:Root\incidents.csv") { Get-Content "$script:Root\incidents.csv" }
    } *>&1 | Out-File $f -Encoding ascii -Width 250
    Log "Evidence bundle saved: $f (stays on this machine; do not upload to scanners, rule 12)" 'OK'
}

function Invoke-Incident {
    $csv = Join-Path $script:Root 'incidents.csv'
    Write-Host ' 1) Log an incident   2) Show incidents   3) Export as markdown'
    switch (Ask 'Select' '1') {
        '1' {
            $what = Ask 'What did you see'; if (-not $what) { return }
            $row = [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Machine = $env:COMPUTERNAME; Severity = (Ask 'Severity (Low/Medium/High/Critical)' 'Medium'); What = $what
                SourceIP = (Ask 'Source IP (if known)'); Evidence = (Ask 'Evidence (log, file, command)'); Action = (Ask 'Action you took') }
            $row | Export-Csv $csv -Append -NoTypeInformation -Encoding ASCII
            Log "INCIDENT logged: $what" 'ACTION'
        }
        '2' { if (Test-Path $csv) { Show-Text (Import-Csv $csv | Format-List) } }
        '3' {
            if (-not (Test-Path $csv)) { return }
            $md = Join-Path $script:Root 'incident-notes.md'; '# Incident notes' | Out-File $md -Encoding ascii
            foreach ($i in Import-Csv $csv) { '' | Add-Content $md; "## $($i.Time) - $($i.Machine) - $($i.Severity)" | Add-Content $md; "- What: $($i.What)", "- Source IP: $($i.SourceIP)", "- Evidence: $($i.Evidence)", "- Action: $($i.Action)" | Add-Content $md }
            Log "Exported your notes to $md (write the inject yourself; rule 21)." 'OK'
        }
    }
}

function Invoke-Status {
    $cfg = $script:RoleCfg[$script:Role]
    Write-Host ("Host {0}   role {1}   team {2}   user {3}" -f $env:COMPUTERNAME, $script:Role, (Get-TeamNumber), $env:USERNAME) -ForegroundColor Cyan
    foreach ($n in (@($cfg.Services) + $script:CoreServices + $script:AccessServices | Select-Object -Unique)) {
        $s = Get-Service $n -ErrorAction SilentlyContinue; if (-not $s) { Write-Host ("  {0,-20} MISSING" -f $n) -ForegroundColor Red; continue }
        $st = Get-ScModeWord (Get-SvcStart $n)
        $c = if ($s.Status -eq 'Running') { 'Green' } elseif ($script:AccessServices -contains $n -and $cfg.Services -notcontains $n) { 'DarkGray' } else { 'Red' }
        Write-Host ("  {0,-20} {1,-9} startup={2}" -f $n, $s.Status, $st) -ForegroundColor $c
    }
    foreach ($p in $cfg.Ports) { $l = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue; Write-Host ("  port {0,-5} {1}" -f $p, $(if ($l) { 'listening' } else { 'NOT LISTENING' })) -ForegroundColor $(if ($l) { 'Green' } else { 'Red' }) }
    Write-Host ('  firewall: ' + ((Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ' '))
    $open = @(Get-JournalEntries | Where-Object { -not $_.undone }).Count
    Write-Host ("  journal entries open: {0}   vault: {1}   snapshots: {2}" -f $open, $(if (Test-Path $script:VaultFile) { 'encrypted' } else { 'none yet' }), @(Get-Snapshots).Count)
    Write-Host '  last log lines:'; if (Test-Path $script:LogFile) { Get-Content $script:LogFile -Tail 6 | ForEach-Object { Write-Host ('    ' + $_) -ForegroundColor DarkGray } }
}

# ---------------- Setup: logging ----------------
function Invoke-Visibility {
    Log 'Enabling advanced audit policy...'
    foreach ($s in 'Process Creation', 'Logon', 'Logoff', 'Special Logon', 'Account Lockout', 'User Account Management', 'Security Group Management', 'Other Account Management Events', 'Credential Validation', 'Security System Extension', 'Other Object Access Events', 'Audit Policy Change', 'Sensitive Privilege Use', 'File Share') {
        auditpol /set /subcategory:"$s" /success:enable /failure:enable 2>&1 | Out-Null
    }
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
    $ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    New-Item -Path "$ps\ScriptBlockLogging" -Force | Out-Null; Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
    New-Item -Path "$ps\ModuleLogging\ModuleNames" -Force | Out-Null; Set-ItemProperty -Path "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord; Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*'
    $tr = Join-Path $script:Root 'ps-transcripts'; New-Item -ItemType Directory -Path $tr -Force | Out-Null; icacls $tr /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
    New-Item -Path "$ps\Transcription" -Force | Out-Null
    Set-ItemProperty -Path "$ps\Transcription" -Name EnableTranscripting -Value 1 -Type DWord; Set-ItemProperty -Path "$ps\Transcription" -Name OutputDirectory -Value $tr
    wevtutil sl Security /ms:536870912 2>&1 | Out-Null; wevtutil sl System /ms:134217728 2>&1 | Out-Null
    wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /e:true /ms:268435456 2>&1 | Out-Null; wevtutil sl 'Microsoft-Windows-WinRM/Operational' /e:true /ms:134217728 2>&1 | Out-Null
    try { Set-NetFirewallProfile -Profile Domain, Private, Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767 } catch { Log "Firewall logging: $_" 'WARN' }
    Log 'Audit policy, command-line capture, PowerShell logging, firewall logging and bigger logs are on.' 'OK'
}

# ---------------- Watchdog ----------------
function Invoke-RegGuardOnce {
    foreach ($r in Get-RegWatchStatus) {
        $w = $r.Item
        if ($r.Status -ne 'DEVIATES' -or $w.K -eq 'Multi' -or $w.Manual -or -not $w.ContainsKey('Good')) { continue }
        try {
            if ($w.Good -eq '' -and $w.Absent) { Remove-RegJournal $w.P $w.N } else { Set-RegJournal $w.P $w.N $(if ($w.K -eq 'DWord') { [int]$w.Good } else { $w.Good }) $w.K }
            Log "REGISTRY GUARD restored $($w.P)\$($w.N) to '$($w.Good)' (was '$($r.Cur)'): $($w.Why)" 'ACTION'
        } catch { Log "Registry guard could not restore $($w.N): $_" 'ALERT' }
    }
}

function Invoke-Watchdog {
    $cfg = $script:RoleCfg[$script:Role]
    if ($script:Role -eq 'generic') { Log 'Role not detected, so the watchdog only covers the Windows core services. Use -Role to set one.' 'WARN' }
    $last = @{}; $tick = 0; $lastRepair = @{}
    function Note { param([string]$Key, [string]$State, [string]$Msg, [string]$Lvl = 'ALERT') if ($last[$Key] -ne $State) { Log $Msg $Lvl; $last[$Key] = $State } }
    $baseShares = $null; $bf = Join-Path $script:Root 'snap\initial\shares.json'
    if ($script:Role -eq 'smb' -and (Test-Path $bf)) { $baseShares = @((Get-Content $bf -Raw | ConvertFrom-Json) | ForEach-Object { $_.Name }) }
    Log "Watchdog started: role=$($script:Role), every ${IntervalSec}s. It enables+starts the scored service and core services, restores their firewall rules, fixes known-good registry values and mirrors logs. Ctrl+C to stop." 'OK'
    while ($true) {
        $problems = 0; $tick++
        $watch = @($cfg.Services) + $script:CoreServices
        foreach ($n in $watch) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            $st = Get-SvcStart $n
            if (-not $s) { if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$n") { $problems++; Note "svc-$n" 'x' "Service $n is not visible to the Service Manager" }; continue }
            if ($st -eq 4 -or $s.Status -ne 'Running') {
                $problems++; Note "svc-$n" 'down' "Service $n is $($s.Status) (startup $(Get-ScModeWord $st)). Repairing..."
                if (-not $lastRepair.ContainsKey($n) -or ((Get-Date) - $lastRepair[$n]).TotalSeconds -gt 60) {
                    $lastRepair[$n] = Get-Date
                    Repair-OneService $n $true $true $false
                }
                $last["svc-$n"] = 'fixed'
            } else { $last["svc-$n"] = 'up' }
        }
        foreach ($p in $cfg.Ports) { if (-not (Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue)) { $problems++; Note "port-$p" 'closed' "Nothing listening on TCP $p" } else { $last["port-$p"] = 'open' } }
        foreach ($rn in $cfg.Rules) {
            $fw = Get-NetFirewallRule -Name $rn -ErrorAction SilentlyContinue
            if ($fw -and ($fw.Enabled -ne 'True' -or $fw.Action -ne 'Allow')) { $problems++; Set-NetFirewallRule -Name $rn -Enabled True -Action Allow; Log "Restored firewall rule $rn" 'ACTION' }
        }
        foreach ($pr in Get-NetFirewallProfile) { if (-not $pr.Enabled) { $problems++; Note "fwp-$($pr.Name)" 'off' "Firewall profile $($pr.Name) was turned OFF" } else { $last["fwp-$($pr.Name)"] = 'on' } }
        try {
            switch ($script:Role) {
                'iis' {
                    Import-Module WebAdministration -ErrorAction Stop
                    foreach ($site in Get-Website) { if ($site.State -ne 'Started') { $problems++; Note "site-$($site.Name)" 'x' "IIS site '$($site.Name)' is $($site.State)"; Start-Website -Name $site.Name; Log "Started site $($site.Name)" 'ACTION' } }
                    foreach ($pool in Get-ChildItem IIS:\AppPools) { if ($pool.State -ne 'Started') { $problems++; Note "pool-$($pool.Name)" 'x' "App pool '$($pool.Name)' is $($pool.State)"; Start-WebAppPool -Name $pool.Name; Log "Started app pool $($pool.Name)" 'ACTION' } }
                }
                'smb' {
                    if ($baseShares) { $now = (Get-SmbShare -ErrorAction Stop).Name; foreach ($b in $baseShares) { if ($now -notcontains $b) { $problems++; Note "share-$b" 'gone' "SMB share '$b' is GONE. Snapshots > Restore > shares will recreate it." } else { $last["share-$b"] = 'ok' } } }
                }
                'winrm' {
                    if (((winrm enumerate winrm/config/listener 2>&1) -join "`n") -notmatch 'Transport = HTTP') { $problems++; Note 'listener' 'gone' 'WinRM HTTP listener (5985) is MISSING'; winrm create 'winrm/config/Listener?Address=*+Transport=HTTP' 2>&1 | Out-Null; Log 'Re-created the WinRM HTTP listener' 'ACTION' }
                }
            }
        } catch { Log "Role check error: $_" 'WARN' }
        if ($tick % 4 -eq 0) { Invoke-RegGuardOnce }
        if ($tick % 20 -eq 0) { Invoke-LogMirror -Minutes 6 -Quiet }
        $stamp = Get-Date -Format 'HH:mm:ss'
        if ($problems -eq 0) { Write-Host "[$stamp] $($script:Role) OK" -ForegroundColor Green } else { Write-Host "[$stamp] $($script:Role) - $problems problem(s), see log" -ForegroundColor Red }
        Start-Sleep -Seconds $IntervalSec
    }
}

# ============================================================================================
#  TRUSTED TOOLS: Sysinternals, curl, and a tamper check of Windows' own tools
#  Downloads go to C:\BlueOps\tools. Sysinternals files are kept only if validly signed by Microsoft, and their hashes are
#  saved so you can re-check the folder later. Needs internet from the box; if it is blocked the script says so and moves on.
# ============================================================================================
$script:ToolsDir  = Join-Path $script:Root 'tools'
$script:SysDir    = Join-Path $script:ToolsDir 'sysinternals'
$script:CurlDir   = Join-Path $script:ToolsDir 'curl'
$script:SysUrl    = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$script:CurlUrl   = 'https://curl.se/windows/latest.cgi?p=win64-mingw.zip'
$script:SysHashes = Join-Path $script:ToolsDir 'sysinternals-hashes.csv'
$script:KeyBins   = @('cmd.exe', 'powershell.exe', 'net.exe', 'net1.exe', 'sc.exe', 'reg.exe', 'curl.exe', 'certutil.exe', 'netsh.exe', 'schtasks.exe',
    'taskkill.exe', 'tasklist.exe', 'whoami.exe', 'ipconfig.exe', 'netstat.exe', 'wevtutil.exe', 'auditpol.exe', 'icacls.exe', 'takeown.exe', 'wmic.exe',
    'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'bitsadmin.exe', 'cscript.exe', 'wscript.exe', 'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe',
    'magnify.exe', 'conhost.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'explorer.exe', 'logoff.exe', 'quser.exe', 'robocopy.exe',
    'findstr.exe', 'attrib.exe', 'nslookup.exe', 'ping.exe', 'msiexec.exe', 'wuauclt.exe')

function Get-WebFileSafe {
    param([string]$Url, [string]$Out, [int]$TimeoutSec = 900)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    $old = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop }
    finally { $ProgressPreference = $old }
}
function Test-WebReachable {
    param([string]$Url)
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $null = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop; return $true }
    catch { return $false }
}
function Get-MsSig {
    param([string]$Path)
    $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    $subj = ''; if ($s -and $s.SignerCertificate) { $subj = [string]$s.SignerCertificate.Subject }
    $st = if ($s) { [string]$s.Status } else { 'Unknown' }
    return [pscustomobject]@{ Status = $st; Subject = $subj; Microsoft = (($st -eq 'Valid') -and ($subj -match 'O=Microsoft Corporation')) }
}
function Get-ToolFiles { return @(Get-ChildItem $script:SysDir -File -Recurse -ErrorAction SilentlyContinue | Where-Object { @('.exe', '.dll', '.sys', '.scr') -contains $_.Extension.ToLower() }) }
function Add-ToolsToPath { if ((Test-Path $script:SysDir) -and ($env:Path -notlike ('*' + $script:SysDir + '*'))) { $env:Path += ';' + $script:SysDir } }

# ---- Rule 12: keep Sysinternals tools from reaching VirusTotal ----
# The VirusTotal switch lives inside Microsoft's programs, so it cannot be deleted. Instead the VirusTotal names are pointed
# at 0.0.0.0 in the hosts file, so even if someone turns the option on, nothing can be sent. Re-applied every time a tool is opened.
$script:VtNames = @('virustotal.com', 'www.virustotal.com', 'vt.virustotal.com')
$script:VtMark  = '# BLUEOPS-VT-BLOCK'
$script:HostsFile = Join-Path $env:windir 'System32\drivers\etc\hosts'
function Test-VtBlocked {
    if (-not (Test-Path $script:HostsFile)) { return $false }
    return [bool](Select-String -Path $script:HostsFile -SimpleMatch $script:VtMark -Quiet -ErrorAction SilentlyContinue)
}
function Block-VirusTotal {
    if (Test-VtBlocked) { return $true }
    try {
        Copy-Item $script:HostsFile (Join-Path $script:Root 'hosts.before-vt') -Force
        $lines = @(); foreach ($n in $script:VtNames) { $lines += ('0.0.0.0 ' + $n + ' ' + $script:VtMark) }
        Add-Content -Path $script:HostsFile -Value $lines -Encoding ASCII -ErrorAction Stop
        ipconfig /flushdns 2>&1 | Out-Null
        Log 'VirusTotal is blocked in the hosts file (rule 12). The hosts file before this change is saved as C:\BlueOps\hosts.before-vt.' 'ACTION'
        return $true
    } catch { Log ('Could not edit the hosts file: ' + $_.Exception.Message + '. Do NOT enable VirusTotal in any tool.') 'ALERT'; return $false }
}

function Install-Sysinternals {
    if (-not (Test-WebReachable $script:SysUrl)) { Log 'Cannot reach download.sysinternals.com from this machine, so Sysinternals was not installed.' 'WARN'; return }
    if (-not (Confirm-YN 'Download the Sysinternals Suite (large: roughly 50-170 MB) from Microsoft into C:\BlueOps\tools?' $true)) { return }
    New-Item -ItemType Directory -Path $script:ToolsDir -Force | Out-Null
    $zip = Join-Path $script:ToolsDir 'SysinternalsSuite.zip'
    try {
        Log 'Downloading the Sysinternals Suite (this can take a few minutes)...' 'INFO'
        Get-WebFileSafe $script:SysUrl $zip
        Log ('Downloaded SysinternalsSuite.zip, SHA256 ' + (Get-FileHash $zip -Algorithm SHA256).Hash) 'INFO'
        if (Test-Path $script:SysDir) { Remove-Item $script:SysDir -Recurse -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $script:SysDir)
    } catch { Log ('Sysinternals download or extract failed: ' + $_.Exception.Message) 'ALERT'; return }
    $good = 0; $bad = 0; $rows = @()
    foreach ($f in (Get-ToolFiles)) {
        $sig = Get-MsSig $f.FullName
        if ($sig.Microsoft) { $good++; $rows += [pscustomobject]@{ Name = $f.Name; Sha256 = (Get-FileHash $f.FullName -Algorithm SHA256).Hash } }
        else { $bad++; Log ("REMOVED {0}: not validly signed by Microsoft ({1})" -f $f.Name, $sig.Status) 'ALERT'; Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue }
    }
    $rows | Export-Csv $script:SysHashes -NoTypeInformation -Encoding ASCII
    Add-ToolsToPath
    [void](Block-VirusTotal)
    Log ("Sysinternals ready in {0}: {1} files verified as Microsoft-signed, {2} removed. Folder added to PATH for this window only." -f $script:SysDir, $good, $bad) 'OK'
    Log 'First launch of a tool shows the Sysinternals license; you accept it yourself. Defender may quarantine PsExec: that is normal. RULE 12: never enable the VirusTotal options in Process Explorer, Autoruns or Sigcheck.' 'WARN'
}
function Test-ToolsTamper {
    if (-not (Test-Path $script:SysHashes)) { Write-Host 'No saved hashes yet. Install Sysinternals first (option 1).'; return }
    $saved = @{}; foreach ($r in (Import-Csv $script:SysHashes)) { $saved[$r.Name] = $r.Sha256 }
    $bad = 0; $seen = @{}
    foreach ($f in (Get-ToolFiles)) {
        $seen[$f.Name] = $true
        $h = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
        if (-not $saved.ContainsKey($f.Name)) { Log ('NEW file in the tools folder: ' + $f.FullName) 'ALERT'; $bad++ }
        elseif ($saved[$f.Name] -ne $h) { Log ('CHANGED since download: ' + $f.Name) 'ALERT'; $bad++ }
        elseif (-not (Get-MsSig $f.FullName).Microsoft) { Log ('Signature no longer valid: ' + $f.Name) 'ALERT'; $bad++ }
    }
    foreach ($k in $saved.Keys) { if (-not $seen.ContainsKey($k)) { Log ('MISSING from the tools folder: ' + $k + ' (deleted, or quarantined by Defender)') 'WARN' } }
    if ($bad -eq 0) { Log ('Tools folder matches the saved hashes ({0} files checked).' -f $seen.Count) 'OK' } else { Log "$bad file(s) in the tools folder look tampered with. Re-download (option 1)." 'ALERT' }
}
function Find-SysBin {
    param([string]$Name)
    foreach ($d in "$env:windir\System32", "$env:windir\System32\WindowsPowerShell\v1.0", $env:windir) { $p = Join-Path $d $Name; if (Test-Path $p) { return $p } }
    return $null
}
function Invoke-SysBinCheck {
    Log 'Checking that Windows own tools are still signed by Microsoft (Red may replace them)...' 'INFO'
    $n = 0; $bad = 0
    foreach ($b in $script:KeyBins) {
        $p = Find-SysBin $b
        if (-not $p) { continue }
        $n++
        $sig = Get-MsSig $p
        if (-not $sig.Microsoft) { $bad++; Log ("TAMPERED? {0}: signature {1} {2}  ({3})" -f $b, $sig.Status, $sig.Subject, $p) 'ALERT' }
    }
    if ($bad -eq 0) { Log "All $n checked Windows tools have a valid Microsoft signature." 'OK' }
    else { Log "$bad of $n Windows tools failed. Run the SFC check (option 6) and treat them as untrusted until repaired. Use PowerShell cmdlets instead of those programs." 'ALERT' }
}
function Invoke-CurlCheck {
    $p = Join-Path $env:windir 'System32\curl.exe'
    if (Test-Path $p) {
        $sig = Get-MsSig $p
        if ($sig.Microsoft) { Log 'Built-in curl.exe is validly signed by Microsoft.' 'OK'; try { Log ([string](& $p --version | Select-Object -First 1)) 'INFO' } catch { } }
        else { Log ("Built-in curl.exe is NOT validly Microsoft-signed ({0}). Treat it as tampered." -f $sig.Status) 'ALERT' }
    } else { Log 'No built-in curl.exe on this Windows build.' 'WARN' }
    Write-Host 'Tip: PowerShell can fetch a page without curl:  Invoke-WebRequest -UseBasicParsing <url>' -ForegroundColor DarkGray
    if (-not (Confirm-YN 'Also download the official curl build from curl.se into C:\BlueOps\tools\curl as a backup copy?' $false)) { return }
    if (-not (Test-WebReachable $script:CurlUrl)) { Log 'Cannot reach curl.se from this machine.' 'WARN'; return }
    New-Item -ItemType Directory -Path $script:ToolsDir -Force | Out-Null
    $zip = Join-Path $script:ToolsDir 'curl-win64.zip'
    try {
        Get-WebFileSafe $script:CurlUrl $zip
        if (Test-Path $script:CurlDir) { Remove-Item $script:CurlDir -Recurse -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $script:CurlDir)
    } catch { Log ('curl download or extract failed: ' + $_.Exception.Message) 'ALERT'; return }
    $exe = Get-ChildItem $script:CurlDir -Recurse -Filter curl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    Log ('Downloaded curl.se zip, SHA256 ' + (Get-FileHash $zip -Algorithm SHA256).Hash) 'INFO'
    Write-Host 'Compare that SHA256 with the one listed for "curl for 64-bit" on https://curl.se/windows/ (check it on your own laptop).' -ForegroundColor Yellow
    Write-Host 'These builds are not signed by a trusted publisher, so Windows cannot vouch for them. It is not added to PATH.' -ForegroundColor Yellow
    if ($exe) { Log ('curl backup copy: ' + $exe.FullName) 'OK' }
}
function Open-SysTool {
    if (-not (Test-Path $script:SysDir)) { Write-Host 'Install Sysinternals first (option 1).'; return }
    $list = @(@('Autoruns (everything that starts automatically)', 'autoruns64.exe'), @('Process Explorer (processes, signatures, handles)', 'procexp64.exe'),
        @('TCPView (live connections and listeners)', 'Tcpview.exe'), @('Process Monitor (file, registry and process activity)', 'Procmon64.exe'))
    $i = 0; foreach ($t in $list) { $i++; Write-Host ("  {0}) {1}" -f $i, $t[0]) }
    $pick = Ask 'Open which (blank = none)'
    if ($pick -notmatch '^[1-4]$') { return }
    $exe = Get-ChildItem $script:SysDir -Recurse -Filter $list[[int]$pick - 1][1] -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) { Log ('Not found in the tools folder: ' + $list[[int]$pick - 1][1]) 'WARN'; return }
    if (-not (Get-MsSig $exe.FullName).Microsoft) { Log 'REFUSED: that file is not validly signed by Microsoft any more. Re-download (option 1).' 'ALERT'; return }
    if (-not (Block-VirusTotal)) { Log 'REFUSED: VirusTotal could not be blocked, so the tool was not opened (rule 12).' 'ALERT'; return }
    Write-Host 'RULE 12: do NOT turn on the VirusTotal options in these tools (Options > VirusTotal.com / Scan options). They send file hashes or files off the network.' -ForegroundColor Yellow
    Start-Process -FilePath $exe.FullName
    Log ('Opened ' + $exe.Name) 'ACTION'
}
function Invoke-ToolsMenu {
    while ($true) {
        Clear-Host
        Write-Host '=== TRUSTED TOOLS ===' -ForegroundColor Cyan
        Write-Host ' 1) Download + verify the Sysinternals Suite (kept only if Microsoft-signed)'
        Write-Host ' 2) Re-check the downloaded tools for tampering (hashes + signatures)'
        Write-Host ' 3) Check Windows own tools for tampering (signatures of about 45 programs)'
        Write-Host ' 4) Check curl (built-in) and optionally download the official curl.se build'
        Write-Host ' 5) Open a Sysinternals tool (Autoruns, Process Explorer, TCPView, Process Monitor)'
        Write-Host ' 6) SFC integrity check (read-only, takes a few minutes)'
        Write-Host ' 7) SFC repair: restore tampered Windows files from the local store (changes files)'
        Write-Host (' 8) Block VirusTotal on this machine (rule 12) - currently: ' + $(if (Test-VtBlocked) { 'BLOCKED' } else { 'not blocked' }))
        Write-Host ' 0) Back'
        switch ((Read-Host 'Select').Trim()) {
            '1' { Install-Sysinternals; Pause-Menu }
            '2' { Test-ToolsTamper; Pause-Menu }
            '3' { Invoke-SysBinCheck; Pause-Menu }
            '4' { Invoke-CurlCheck; Pause-Menu }
            '5' { Open-SysTool; Pause-Menu }
            '6' { Log 'Running sfc /verifyonly ...' 'INFO'; & "$env:windir\System32\sfc.exe" /verifyonly; Pause-Menu }
            '7' { if (Confirm-Yes 'Run sfc /scannow? It replaces damaged Windows system files with good copies (only Windows files, not scored services).') { & "$env:windir\System32\sfc.exe" /scannow; Log 'SFC repair finished; read its summary above.' 'ACTION' }; Pause-Menu }
            '8' { [void](Block-VirusTotal); Pause-Menu }
            '0' { return }
        }
    }
}

# ============================================================================================
#  ROLE TOOLS
# ============================================================================================
# ---------------- transporters: SMB ----------------
function Invoke-SmbAudit {
    $cfg = Get-SmbServerConfiguration
    Show-Text ($cfg | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature, EncryptData, AutoShareServer | Format-List)
    if ($cfg.EnableSMB1Protocol) { Log 'SMBv1 is ENABLED' 'ALERT' }
    $lan = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $ns = (Get-ItemProperty $lan -ErrorAction SilentlyContinue).NullSessionShares
    Log ("RestrictAnonymous={0} RestrictNullSessAccess={1} NullSessionShares=[{2}]" -f (Get-RegRaw $lsa 'RestrictAnonymous'), (Get-RegRaw $lan 'RestrictNullSessAccess'), ($ns -join ','))
    if ($ns) { Log 'NullSessionShares is populated: anonymous access to those shares is possible' 'ALERT' }
    $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue; if ($g -and $g.Enabled) { Log 'Guest account is ENABLED' 'ALERT' }
    $weak = 'Everyone', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\Users', 'NT AUTHORITY\ANONYMOUS LOGON', 'BUILTIN\Guests'
    $shares = @(Get-SmbShare)
    foreach ($s in $shares) {
        Log ("Share {0} -> {1} {2}" -f $s.Name, $s.Path, $(if ($s.Special) { '(default admin share)' } else { '' }))
        if (-not $s.Special -and $s.Name -like '*$') { Log "Hidden non-default share '$($s.Name)'" 'ALERT' }
        if (-not $s.Special -and $s.Path -match '^[A-Za-z]:\\?$') { Log "Share '$($s.Name)' exposes a drive root" 'ALERT' }
        if (-not $s.Special -and $s.Path -match '(?i)\\Windows(\\|$)') { Log "Share '$($s.Name)' exposes the Windows directory" 'ALERT' }
        foreach ($a in Get-SmbShareAccess -Name $s.Name) {
            $line = '    {0,-40} {1,-8} {2}' -f $a.AccountName, $a.AccessRight, $a.AccessControlType
            if (($weak -contains $a.AccountName) -and ($a.AccessRight -in 'Full', 'Change') -and ($a.AccessControlType -eq 'Allow') -and -not $s.Special) { Log ($line + '   <-- broad write access') 'ALERT' } else { Write-Host $line }
        }
    }
    $mins = [int](Ask 'Look for files changed in the last N minutes' '120'); $since = (Get-Date).AddMinutes(-$mins)
    $bin = '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.scr', '.lnk', '.msi'
    foreach ($s in $shares | Where-Object { -not $_.Special -and $_.Path }) {
        Get-ChildItem -Path $s.Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $isBin = $bin -contains $_.Extension.ToLower()
            if ($_.LastWriteTime -gt $since -or $isBin) { Log ("[{0}] {1} ({2}){3}" -f $s.Name, $_.FullName, $_.LastWriteTime, $(if ($isBin) { '  executable/script in a share' } else { '' })) $(if ($isBin) { 'ALERT' } else { 'WARN' }) }
        }
    }
    Write-Host '--- Connected clients ---'
    Show-Text (Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsIdle | Format-Table -AutoSize)
    Show-Text (Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, Path | Format-Table -AutoSize)
}
function Invoke-SmbTools {
    while ($true) {
        Clear-Host; Write-Host '=== SMB TOOLS (transporters) ===' -ForegroundColor Cyan
        Write-Host ' 1) Audit shares, permissions, files and connected clients'
        Write-Host ' 2) Close SMB sessions from a client (then block its IP from Attack surface)'
        Write-Host ' 3) Safe hardening: disable SMBv1, null sessions, anonymous enumeration, Guest'
        Write-Host ' 4) Require SMB signing (may fail the scorer: check Hermes right away)'
        Write-Host ' 0) Back'
        switch ((Read-Host 'Select').Trim()) {
            '1' { Invoke-SmbAudit; Pause-Menu }
            '2' { $c = Ask 'Client computer name or IP'; if ($c) { Close-SmbSession -ClientComputerName $c -Force -ErrorAction SilentlyContinue; Close-SmbSession -ClientComputerName "\\$c" -Force -ErrorAction SilentlyContinue; Log "Closed SMB sessions from $c" 'ACTION' }; Pause-Menu }
            '3' {
                $lan = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                if (Confirm-Yes 'Apply the safe SMB hardening (changes are recorded; undo from Snapshots)?') {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
                    Set-RegJournal $lan 'RestrictNullSessAccess' 1 'DWord'
                    Remove-RegJournal $lan 'NullSessionShares'; Remove-RegJournal $lan 'NullSessionPipes'
                    Set-RegJournal $lsa 'RestrictAnonymous' 1 'DWord'; Set-RegJournal $lsa 'EveryoneIncludesAnonymous' 0 'DWord'
                    $g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue; if ($g -and $g.Enabled) { Disable-LocalUser Guest; [void](Add-Journal 'user' @{ name = 'Guest' }) }
                    Log 'SMB hardening applied. Check Hermes.' 'ACTION'
                }
                Pause-Menu
            }
            '4' { if ((Confirm-Rule10 'Requiring SMB signing') -and (Confirm-Yes 'Require SMB signing? (revert: Set-SmbServerConfiguration -RequireSecuritySignature $false -Force)')) { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false; Log 'SMB signing required. CHECK HERMES.' 'WARN' }; Pause-Menu }
            '0' { return }
        }
    }
}

# ---------------- stewards: IIS ----------------
function Get-IisRoots {
    Import-Module WebAdministration -ErrorAction Stop
    $roots = @()
    foreach ($site in Get-Website) {
        $roots += @{ Site = $site.Name; Path = [Environment]::ExpandEnvironmentVariables($site.PhysicalPath) }
        foreach ($vd in Get-WebVirtualDirectory -Site $site.Name -ErrorAction SilentlyContinue) {
            $vp = [Environment]::ExpandEnvironmentVariables($vd.PhysicalPath)
            if ($vp -and (Test-Path $vp)) { $roots += @{ Site = ($site.Name + '_vd_' + ($vd.Path -replace '[\\/]', '_')); Path = $vp } }
        }
    }
    return $roots
}
function Get-WebHashes { param($Roots) foreach ($r in $Roots) { if (Test-Path $r.Path) { Get-ChildItem $r.Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } } } } }

function Invoke-IisAudit {
    $roots = Get-IisRoots
    foreach ($site in Get-Website) {
        $b = ($site.Bindings.Collection | ForEach-Object { '{0} {1}' -f $_.protocol, $_.bindingInformation }) -join '; '
        Log ("Site '{0}' [{1}] pool={2} path={3} bindings={4}" -f $site.Name, $site.State, $site.ApplicationPool, [Environment]::ExpandEnvironmentVariables($site.PhysicalPath), $b)
    }
    foreach ($pool in Get-ChildItem IIS:\AppPools) {
        $pm = $pool.processModel; $line = "Pool '{0}' [{1}] identity={2} user={3}" -f $pool.Name, $pool.State, $pm.identityType, $pm.userName
        if ($pm.identityType -eq 'LocalSystem') { Log ($line + '  <-- runs as SYSTEM') 'ALERT' } elseif ($pm.identityType -eq 'SpecificUser') { Log ($line + '  <-- custom account: confirm it is not an admin') 'WARN' } else { Write-Host $line }
    }
    $appcmd = Find-Appcmd; $modFile = Join-Path $script:Root 'iis-modules-baseline.txt'
    if ($appcmd) {
        $mods = & $appcmd list modules | Sort-Object
        if (-not (Test-Path $modFile)) { $mods | Out-File $modFile -Encoding ascii; Log 'Saved the IIS module list as a baseline.' 'INFO' }
        else { $d = Compare-Object (Get-Content $modFile) $mods; if ($d) { foreach ($x in $d) { Log ("IIS module change {0} {1}" -f $x.SideIndicator, $x.InputObject) 'ALERT' } } else { Log 'IIS module list unchanged.' 'OK' } }
    }
    try { Get-WebConfiguration '//system.webServer/handlers/add' | Where-Object { $_.scriptProcessor -and ([Environment]::ExpandEnvironmentVariables($_.scriptProcessor) -notmatch '(?i)\\Windows\\') } | ForEach-Object { Log ("Handler {0} path={1} processor={2}" -f $_.name, $_.path, $_.scriptProcessor) 'WARN' } } catch { }
    $weakIds = 'IUSR', 'IIS_IUSRS', 'Users', 'Everyone', 'Authenticated Users'
    foreach ($r in $roots) {
        if (-not (Test-Path $r.Path)) { continue }
        foreach ($ace in (Get-Acl $r.Path).Access) {
            $who = ($ace.IdentityReference.Value -split '\\')[-1]
            if (($weakIds -contains $who) -and $ace.AccessControlType -eq 'Allow' -and "$($ace.FileSystemRights)" -match 'Write|Modify|FullControl|CreateFiles|AppendData') { Log ("{0}: {1} has {2} on the web root" -f $r.Path, $ace.IdentityReference, $ace.FileSystemRights) 'ALERT' }
        }
    }
}
function Invoke-IisHunt {
    $roots = Get-IisRoots; $mins = [int](Ask 'Recently-modified window in minutes' '120'); $since = (Get-Date).AddMinutes(-$mins)
    $scriptExt = '.asp', '.aspx', '.ashx', '.asmx', '.ascx', '.cer', '.asa', '.php', '.jsp', '.config', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta'
    $binExt = '.exe', '.dll', '.scr', '.msi', '.sys'
    $rx = '(?i)eval\s*\(|cmd\.exe|powershell|WScript\.Shell|Shell\.Application|Process\.Start|ProcessStartInfo|System\.Diagnostics\.Process|FromBase64String|Server\.Execute|Response\.BinaryWrite|Scripting\.FileSystemObject|certutil|bitsadmin|Invoke-Expression|IEX\s*\('
    foreach ($r in $roots) {
        if (-not (Test-Path $r.Path)) { continue }
        foreach ($f in Get-ChildItem $r.Path -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $ext = $f.Extension.ToLower()
            if ($f.Name -match '(?i)\.(jpg|jpeg|png|gif|txt|pdf|css)\.(asp|aspx|ashx|php|jsp|cer)$') { Log "Double extension: $($f.FullName)" 'ALERT' }
            if (($binExt -contains $ext) -and ($f.FullName -notmatch '(?i)\\bin\\')) { Log "Binary in web root outside \bin: $($f.FullName)" 'ALERT' }
            if ($f.LastWriteTime -gt $since -and (($scriptExt + $binExt) -contains $ext)) { Log ("Recently modified {0}: {1} ({2})" -f $ext, $f.FullName, $f.LastWriteTime) 'WARN' }
            if (($scriptExt -contains $ext) -and $f.Length -lt 2MB) {
                $hit = Select-String -Path $f.FullName -Pattern $rx -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($hit) { $t = $hit.Line.Trim(); Log ("Suspicious content in {0} line {1}: {2}" -f $f.FullName, $hit.LineNumber, $t.Substring(0, [Math]::Min(120, $t.Length))) 'ALERT' }
            }
        }
    }
    Log 'Webshell hunt finished.' 'OK'
}
function Invoke-IisLogs {
    $files = Get-ChildItem 'C:\inetpub\logs\LogFiles' -Recurse -Filter *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
    $sus = '(?i)cmd=|cmd\.exe|powershell|whoami|certutil|%00|\.\./|\.\.%2f|%2e%2e|union(\+|%20)select|<script|etc/passwd|net\+user|ipconfig|\.(ashx|asmx|php|jsp)|c99|r57|b374k|webshell'
    foreach ($lf in $files) {
        Log "Log: $($lf.FullName)"
        $lines = Get-Content $lf.FullName -Tail 5000
        $fields = ($lines | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1) -replace '^#Fields:\s*', ''
        $idx = if ($fields) { [array]::IndexOf(($fields -split ' '), 'c-ip') } else { -1 }
        if ($idx -ge 0) { Write-Host '  Top client IPs:'; $lines | Where-Object { $_ -notlike '#*' } | ForEach-Object { ($_ -split ' ')[$idx] } | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '   {0,6}  {1}' -f $_.Count, $_.Name } | Out-String | Write-Host }
        Write-Host '  Suspicious requests (most recent):'
        $lines | Where-Object { $_ -notlike '#*' -and $_ -match $sus } | Select-Object -Last 40 | ForEach-Object { Write-Host ('   ' + $_) -ForegroundColor Yellow }
    }
}
function Invoke-IisTools {
    $hashFile = Join-Path $script:Root 'iis-hashes.csv'; $backupRoot = Join-Path $script:Root 'iis-backup'
    while ($true) {
        Clear-Host; Write-Host '=== IIS TOOLS (stewards) ===' -ForegroundColor Cyan
        Write-Host ' 1) Audit sites, app pools, modules, handlers, web root permissions'
        Write-Host ' 2) Save hashes of the web content (do this EARLY, before Red edits pages)'
        Write-Host ' 3) Check web content against saved hashes (new / changed / deleted files)'
        Write-Host ' 4) Back up the web root now'
        Write-Host ' 5) RESTORE the web root from backup (removes files not in the backup)'
        Write-Host ' 6) Webshell / tampering hunt'
        Write-Host ' 7) Read IIS request logs (top IPs, suspicious requests)'
        Write-Host ' 8) Disable directory browsing (check Hermes afterwards)'
        Write-Host ' 0) Back'
        $c = (Read-Host 'Select').Trim()
        try {
            switch ($c) {
                '1' { Invoke-IisAudit; Pause-Menu }
                '2' {
                    if ((Test-Path $hashFile) -and -not (Confirm-YN 'Hashes already saved. Overwrite? (only if you know the content is clean)' $false)) { Pause-Menu; continue }
                    Get-WebHashes (Get-IisRoots) | Export-Csv $hashFile -NoTypeInformation -Encoding ASCII; Log "Saved web hashes to $hashFile" 'ACTION'; Pause-Menu
                }
                '3' {
                    if (-not (Test-Path $hashFile)) { Write-Host 'No hash baseline yet (option 2).' } else {
                        $old = @{}; foreach ($o in Import-Csv $hashFile) { $old[$o.Path] = $o.Hash }; $seen = @{}; $n = 0
                        foreach ($x in Get-WebHashes (Get-IisRoots)) { $seen[$x.Path] = $true; if (-not $old.ContainsKey($x.Path)) { $n++; Log "NEW file: $($x.Path)" 'ALERT' } elseif ($old[$x.Path] -ne $x.Hash) { $n++; Log "CHANGED file: $($x.Path)" 'ALERT' } }
                        foreach ($p in $old.Keys) { if (-not $seen.ContainsKey($p)) { $n++; Log "DELETED file: $p" 'ALERT' } }
                        if ($n -eq 0) { Log 'Web content matches the saved hashes.' 'OK' }
                    }
                    Pause-Menu
                }
                '4' {
                    foreach ($r in Get-IisRoots) {
                        $dest = Join-Path $backupRoot $r.Site
                        if ((Test-Path $dest) -and -not (Confirm-YN "A backup for '$($r.Site)' exists. Replace it? (only if the site is clean now)" $false)) { continue }
                        robocopy $r.Path $dest /MIR /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
                        if ($LASTEXITCODE -ge 8) { Log "robocopy error backing up $($r.Path)" 'ALERT' } else { Log "Backed up $($r.Path) -> $dest" 'ACTION' }
                    }
                    Pause-Menu
                }
                '5' {
                    foreach ($r in Get-IisRoots) {
                        $src = Join-Path $backupRoot $r.Site
                        if (-not (Test-Path $src)) { Log "No backup for '$($r.Site)'" 'WARN'; continue }
                        if (Confirm-Yes "Mirror the backup over $($r.Path)? Files not in the backup are deleted.") {
                            robocopy $src $r.Path /MIR /COPY:DAT /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
                            if ($LASTEXITCODE -ge 8) { Log "robocopy error restoring $($r.Path)" 'ALERT' } else { Log "Restored $($r.Path)" 'ACTION' }
                        }
                    }
                    Pause-Menu
                }
                '6' { Invoke-IisHunt; Pause-Menu }
                '7' { Invoke-IisLogs; Pause-Menu }
                '8' { if ((Confirm-Rule10 'Disabling directory browsing') -and (Confirm-YN 'Disable directory browsing server-wide?' $false)) { Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -PSPath 'MACHINE/WEBROOT/APPHOST' -Name enabled -Value $false; Log 'Directory browsing disabled. Check Hermes.' 'ACTION' }; Pause-Menu }
                '0' { return }
            }
        } catch { Log "IIS tool error: $_" 'ALERT'; Pause-Menu }
    }
}

# ---------------- teamradio: WinRM ----------------
function Invoke-WinrmAudit {
    $svc = Get-Service WinRM -ErrorAction SilentlyContinue
    Log ("WinRM service: {0}, startup {1}" -f $svc.Status, (Get-ScModeWord (Get-SvcStart 'WinRM'))) $(if ($svc.Status -eq 'Running') { 'OK' } else { 'ALERT' })
    winrm enumerate winrm/config/listener 2>&1 | Out-String | Write-Host
    foreach ($a in Get-ChildItem WSMan:\localhost\Service\Auth -ErrorAction SilentlyContinue) {
        $line = '  {0,-12} = {1}' -f $a.Name, $a.Value
        if (($a.Name -in 'Basic', 'CredSSP') -and $a.Value -eq 'true') { Log ($line + '   <-- weak, confirm whether scoring needs it') 'WARN' } else { Write-Host $line }
    }
    $unenc = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
    $th = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    Log ("AllowUnencrypted={0} TrustedHosts='{1}' IPv4Filter='{2}'" -f $unenc, $th, (Get-Item WSMan:\localhost\Service\IPv4Filter -ErrorAction SilentlyContinue).Value)
    if ($th -eq '*') { Log 'TrustedHosts is *' 'ALERT' }
    $default = 'microsoft.powershell', 'microsoft.powershell.workflow', 'microsoft.powershell32', 'microsoft.windows.servermanagerworkflows', 'windows powershell'
    foreach ($c in Get-PSSessionConfiguration -ErrorAction SilentlyContinue) {
        $line = '  endpoint {0} enabled={1} runas={2}' -f $c.Name, $c.Enabled, $c.RunAsUser
        if ($default -notcontains $c.Name.ToLower() -and $c.Name -notmatch '(?i)^PowerShell\.\d') { Log ($line + '   <-- not a default endpoint (persistence trick)') 'ALERT' } elseif ($c.RunAsUser) { Log ($line + '   <-- RunAs set') 'ALERT' } else { Write-Host $line }
    }
    Write-Host '--- Who can use WinRM ---'; net localgroup 'Remote Management Users' 2>&1 | Out-String | Write-Host
    Write-Host '--- Active remote shells ---'
    try { $sh = Get-WSManInstance -ResourceURI shell -Enumerate -ErrorAction Stop; if ($sh) { Show-Text ($sh | Select-Object ShellId, Owner, ClientIP, ShellRunTime, ShellInactivity | Format-Table -AutoSize) } else { Write-Host '  none' } } catch { Write-Host '  none, or not readable' }
}
function Invoke-WinrmTools {
    while ($true) {
        Clear-Host; Write-Host '=== WINRM TOOLS (teamradio) ===' -ForegroundColor Cyan
        Write-Host ' 1) Audit WinRM: listeners, auth, endpoints, active shells'
        Write-Host ' 2) Delete an active remote shell by ShellId'
        Write-Host ' 3) Show suspicious PowerShell script blocks (needs Setup > Visibility)'
        Write-Host ' 4) Disable Basic authentication (may fail the scorer: check Hermes)'
        Write-Host ' 5) Set AllowUnencrypted = false (may fail the scorer: check Hermes)'
        Write-Host ' 6) Clear TrustedHosts'
        Write-Host ' 0) Back'
        try {
            switch ((Read-Host 'Select').Trim()) {
                '1' { Invoke-WinrmAudit; Pause-Menu }
                '2' { $id = Ask 'ShellId'; if ($id) { Remove-WSManInstance -ResourceURI shell -SelectorSet @{ ShellId = $id } -ErrorAction Stop; Log "Deleted remote shell $id (block the source IP too)" 'ACTION' }; Pause-Menu }
                '3' {
                    $m = [int](Ask 'Minutes back' '120')
                    $rx = '(?i)FromBase64String|DownloadString|DownloadFile|Invoke-Expression|IEX|-enc|Net\.Sockets|sekurlsa|VirtualAlloc|WebClient|schtasks|net\s+user|net\s+localgroup|Stop-Service|Set-Service|Clear-EventLog'
                    $n = 0
                    foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = (Get-Date).AddMinutes(-$m) } -ErrorAction SilentlyContinue) {
                        if ($e.Message -match $rx -and $e.Message -notmatch 'BlueMenu|BlueOps' -and -not (Test-DatadogName $e.Message)) { $n++; $t = ($e.Message -replace '\s+', ' '); Log ("{0} {1}" -f $e.TimeCreated.ToString('HH:mm:ss'), $t.Substring(0, [Math]::Min(300, $t.Length))) 'ALERT' }
                    }
                    if ($n -eq 0) { Write-Host '  none found (is script-block logging on? Setup > Visibility)' }
                    Pause-Menu
                }
                '4' { if ((Confirm-Rule10 'Disabling Basic authentication') -and (Confirm-Yes 'Disable Basic auth? (revert: Set-Item WSMan:\localhost\Service\Auth\Basic $true)')) { Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false; Log 'Basic auth disabled. CHECK HERMES.' 'WARN' }; Pause-Menu }
                '5' { if ((Confirm-Rule10 'Setting AllowUnencrypted to false') -and (Confirm-Yes 'Set AllowUnencrypted=false? (revert: Set-Item WSMan:\localhost\Service\AllowUnencrypted $true)')) { Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false; Log 'AllowUnencrypted=false. CHECK HERMES.' 'WARN' }; Pause-Menu }
                '6' { Set-Item WSMan:\localhost\Client\TrustedHosts -Value '' -Force; Log 'TrustedHosts cleared.' 'ACTION'; Pause-Menu }
                '0' { return }
            }
        } catch { Log "WinRM tool error: $_" 'ALERT'; Pause-Menu }
    }
}

# ============================================================================================
#  QUICK START + MENU
# ============================================================================================
function Save-ServiceBaseline {
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
        $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
        [pscustomobject]@{ Name = $_.PSChildName; Start = "$($p.Start)"; ImagePath = "$($p.ImagePath)"; ObjectName = "$($p.ObjectName)" }
    } | Export-Csv $script:SvcBase -NoTypeInformation -Encoding ASCII
}
function Invoke-QuickStart {
    Write-Host 'Quick start will: snapshot the config, turn on logging + registry auditing, enable/start the role and core services,' -ForegroundColor Cyan
    Write-Host 'fix known-bad registry values, save baselines, audit accounts, run the hunt, and run this host''s audit. Nothing is rotated or disabled.' -ForegroundColor Cyan
    if (-not (Confirm-YN 'Run it?' $true)) { return }
    New-ConfigSnapshot -Label 'initial' -NoPrompt
    Invoke-Visibility
    Invoke-ExtraAuditing
    $cfg = $script:RoleCfg[$script:Role]
    foreach ($n in (@($cfg.Services) + $script:CoreServices | Select-Object -Unique)) { Repair-OneService $n $true $true $true }
    Invoke-RegGuardOnce
    $h = [ordered]@{}; foreach ($w in $script:RegWatch) { $v = Get-RegRaw $w.P $w.N; $h[($w.P + '|' + $w.N)] = $(if ($null -eq $v) { '<absent>' } else { $v }) }
    $h | ConvertTo-Json | Set-Content $script:RegBase -Encoding ASCII
    Save-ServiceBaseline
    Log 'Baselines saved (registry watch + services).' 'ACTION'
    Show-AccountAudit
    Invoke-Hunt
    Invoke-SpyHunt
    Invoke-StartupReview -ReportOnly
    Invoke-SysBinCheck
    try { Install-Sysinternals } catch { Log ('Sysinternals step skipped: ' + $_.Exception.Message) 'WARN' }
    switch ($script:Role) { 'smb' { Invoke-SmbAudit } 'iis' { Invoke-IisAudit; Get-WebHashes (Get-IisRoots) | Export-Csv (Join-Path $script:Root 'iis-hashes.csv') -NoTypeInformation -Encoding ASCII; Log 'IIS: web hashes saved. Back up the web root from IIS tools > 4.' 'ACTION' } 'winrm' { Invoke-WinrmAudit } }
    Log 'Quick start finished. Review the ALERT lines, then open the watchdog (Setup).' 'OK'
}

function Start-WatchdogWindow {
    if (-not $PSCommandPath) { Write-Host 'Save this file to disk and run it from there so it can open a second window, or run it again with -Watchdog.'; return }
    Start-Process powershell.exe -ArgumentList '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Watchdog', '-Role', $script:Role, '-IntervalSec', "$IntervalSec"
    Log 'Watchdog opened in a new window.' 'ACTION'
}

$script:MenuItems = @(
    @{ G = 'Situation'; T = 'Status dashboard'; R = 'all'; A = { Invoke-Status } }
    @{ G = 'Situation'; T = 'QUICK START (first 5 minutes)'; R = 'all'; A = { Invoke-QuickStart } }
    @{ G = 'Situation'; T = 'What changed, and who did it (last N minutes)'; R = 'all'; A = { Invoke-ChangeTimeline } }
    @{ G = 'Situation'; T = 'Threat hunt (processes, connections, files, backdoors, WMI)'; R = 'all'; A = { Invoke-Hunt } }
    @{ G = 'Situation'; T = 'Screen-watchers, keyloggers, remote-control tools (report only)'; R = 'all'; A = { Invoke-SpyHunt } }
    @{ G = 'Situation'; T = 'Remote logons, failed logons, account/service changes'; R = 'all'; A = { Invoke-Logons } }
    @{ G = 'Situation'; T = 'Incident notes (log / show / export)'; R = 'all'; A = { Invoke-Incident } }
    @{ G = 'Situation'; T = 'Evidence bundle for an incident report'; R = 'all'; A = { Invoke-Evidence } }
    @{ G = 'Tamper defense'; T = 'ENABLE + START services now (role + core, with dependencies)'; R = 'all'; A = { Invoke-ServiceGuard } }
    @{ G = 'Tamper defense'; T = 'Service audit (start type, binary path, logon, FailureCommand, ServiceDll)'; R = 'all'; A = { Invoke-ServiceAudit } }
    @{ G = 'Tamper defense'; T = 'Registry watch (check / baseline / restore known-bad values)'; R = 'all'; A = { Invoke-RegWatch } }
    @{ G = 'Tamper defense'; T = 'Event log health + repair (cleared? disabled? where to look)'; R = 'all'; A = { Invoke-EventLogHealth } }
    @{ G = 'Tamper defense'; T = 'Copy recent logs to a safe folder now'; R = 'all'; A = { Invoke-LogMirror -Minutes ([int](Ask 'Minutes of logs to copy' '30')) } }
    @{ G = 'Tamper defense'; T = 'Turn on extra log channels + registry change auditing'; R = 'all'; A = { Invoke-ExtraAuditing } }
    @{ G = 'Accounts'; T = 'Accounts: rotate, show passwords, test login, open shell as user'; R = 'all'; NP = $true; A = { Invoke-AccountsMenu } }
    @{ G = 'Attack surface'; T = 'Startup & persistence review (disable safely, reversible)'; R = 'all'; A = { Invoke-StartupReview } }
    @{ G = 'Attack surface'; T = 'Listening ports review (service / process / firewall actions)'; R = 'all'; A = { Invoke-PortReview } }
    @{ G = 'Attack surface'; T = 'Risky services (Spooler, RemoteRegistry, UPnP, ...)'; R = 'all'; A = { Invoke-RiskyServices } }
    @{ G = 'Attack surface'; T = 'Firewall review (custom / allow-all inbound rules)'; R = 'all'; A = { Invoke-FirewallReview } }
    @{ G = 'Attack surface'; T = 'Sessions and who is connected (log off a session)'; R = 'all'; A = { Invoke-Sessions } }
    @{ G = 'Attack surface'; T = 'Block / unblock a single IP'; R = 'all'; A = { Invoke-BlockIp } }
    @{ G = 'Snapshots & undo'; T = 'Create a config snapshot'; R = 'all'; A = { New-ConfigSnapshot } }
    @{ G = 'Snapshots & undo'; T = 'List snapshots'; R = 'all'; A = { Show-Snapshots } }
    @{ G = 'Snapshots & undo'; T = 'RESTORE from a snapshot (per component)'; R = 'all'; A = { Restore-ConfigSnapshot } }
    @{ G = 'Snapshots & undo'; T = 'Undo changes made by this script (journal)'; R = 'all'; A = { Invoke-UndoMenu } }
    @{ G = 'This host'; T = 'SMB tools (transporters)'; R = 'smb'; NP = $true; A = { Invoke-SmbTools } }
    @{ G = 'This host'; T = 'IIS tools (stewards)'; R = 'iis'; NP = $true; A = { Invoke-IisTools } }
    @{ G = 'This host'; T = 'WinRM tools (teamradio)'; R = 'winrm'; NP = $true; A = { Invoke-WinrmTools } }
    @{ G = 'Setup'; T = 'Trusted tools: Sysinternals, curl, tamper check of Windows tools'; R = 'all'; NP = $true; A = { Invoke-ToolsMenu } }
    @{ G = 'Setup'; T = 'Open the WATCHDOG in a new window (keeps services up, fixes registry, mirrors logs)'; R = 'all'; A = { Start-WatchdogWindow } }
    @{ G = 'Setup'; T = 'Logging: audit policy, command lines, PowerShell + firewall logging'; R = 'all'; A = { Invoke-Visibility } }
)

function Show-Menu {
    while ($true) {
        Clear-Host
        Write-Host ('=' * 78) -ForegroundColor Cyan
        Write-Host ("  BLUE OPS   host: {0}   role: {1}   team: {2}" -f $env:COMPUTERNAME.ToUpper(), $script:Role, (Get-TeamNumber)) -ForegroundColor Cyan
        Write-Host ('=' * 78) -ForegroundColor Cyan
        $vis = @($script:MenuItems | Where-Object { $_.R -eq 'all' -or $_.R -eq $script:Role })
        $i = 0; $grp = ''
        foreach ($m in $vis) {
            if ($m.G -ne $grp) { $grp = $m.G; Write-Host ''; Write-Host "  $grp" -ForegroundColor Yellow }
            $i++; Write-Host ('   {0,2}) {1}' -f $i, $m.T)
        }
        Write-Host ''
        Write-Host '    R) change role      0) exit' -ForegroundColor DarkGray
        $c = (Read-Host 'Enter an option').Trim().ToLower()
        if ($c -eq '0' -or $c -eq 'q') { return }
        if ($c -eq 'r') {
            $nr = Ask 'Role (smb / iis / winrm / generic)' $script:Role
            if ($script:RoleCfg.ContainsKey($nr)) { $script:Role = $nr }
            continue
        }
        if ($c -match '^\d+$' -and [int]$c -ge 1 -and [int]$c -le $vis.Count) {
            $m = $vis[[int]$c - 1]
            Write-Host ''
            try { & $m.A } catch { Log "Error: $($_.Exception.Message)" 'ALERT' }
            if (-not $m.NP) { Write-Host ''; Pause-Menu }
        }
    }
}

# ============================================================================================
#  MAIN
# ============================================================================================
Assert-Admin
if (-not $Role) { $Role = Get-BlueRole }
$script:Role = $Role
if ($Watchdog) { Invoke-Watchdog; return }
Show-Menu
