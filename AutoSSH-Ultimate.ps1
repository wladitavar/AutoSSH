<#
  AutoSSH-Ultimate.ps1 – Final 2025 Edition
  All configuration & secrets loaded from plain config.json
  Works perfectly on Windows PowerShell 5.1 + NSSM service
#>

# ────────────────────── LOAD CONFIG FROM config.json ──────────────────────
$ScriptPath = $PSScriptRoot
$ConfigFile = Join-Path $ScriptPath "config.json"

if (-not (Test-Path $ConfigFile)) {
    Write-Host @"
FATAL: config.json not found!

Create it in the same folder as this script with this content:

{
    "WebPort": 8855,
    "EnableWeb": true,

    "EnableTelegram": true,
    "TelegramToken": "1234567890:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "TelegramChatID": "-1001234567890",

    "EnableWhatsApp": false,
    "TwilioSID": "",
    "TwilioToken": "",
    "TwilioFrom": "",
    "TwilioTo": "",

    "ScriptUrl": "https://example.com/AutoSSH-Ultimate.ps1",

    "CheckInterval": 7,
    "HealthCheckInterval": 30,
    "PortCheckInterval": 15,
    "RestartDelay": 12
}
"@
    exit 1
}

try {
    $UserConfig = Get-Content $ConfigFile -Raw | ConvertFrom-Json
} catch {
    Write-Host "FATAL: config.json is invalid JSON!" -ForegroundColor Red
    exit 1
}

# ────────────────────── FINAL CONFIGURATION ──────────────────────
$Config = @{
    ConfigFile          = Join-Path $ScriptPath "AutoSSH.tsv"
    LogFile             = Join-Path $ScriptPath "AutoSSH.log"
    LockFile            = Join-Path $ScriptPath "AutoSSH.lock"
    ControlDir          = Join-Path $env:TEMP "ssh-control-auto"

    WebPort             = $UserConfig.WebPort
    EnableWeb           = $UserConfig.EnableWeb

    EnableTelegram      = $UserConfig.EnableTelegram
    TelegramToken       = $UserConfig.TelegramToken
    TelegramChatID      = $UserConfig.TelegramChatID

    EnableWhatsApp      = $UserConfig.EnableWhatsApp
    TwilioSID           = $UserConfig.TwilioSID
    TwilioToken         = $UserConfig.TwilioToken
    TwilioFrom          = $UserConfig.TwilioFrom
    TwilioTo            = $UserConfig.TwilioTo

    ScriptUrl           = $UserConfig.ScriptUrl

    CheckInterval       = $UserConfig.CheckInterval
    HealthCheckInterval = $UserConfig.HealthCheckInterval
    PortCheckInterval   = $UserConfig.PortCheckInterval
    StartupGracePeriod  = 8
    RestartDelay        = $UserConfig.RestartDelay
    AutoUpdateCheck     = 3600

    ServerAliveInterval = 30
    ServerAliveCountMax = 3
    StrictHostKeyChecking = "accept-new"
}

# Create control directory
if (-not (Test-Path $Config.ControlDir)) { New-Item -Path $Config.ControlDir -ItemType Directory -Force | Out-Null }

# ────────────────────── LOGGING + EVENT LOG ──────────────────────
$EventSource = "AutoSSH Ultimate"
if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
    try { New-EventLog -LogName Application -Source $EventSource -ErrorAction SilentlyContinue } catch {}
}

function Log($Message, $Level = "Information", $EventID = 1000) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts [$Level] $Message" | Out-File -FilePath $Config.LogFile -Append -Encoding utf8
    try {
        Write-EventLog -LogName Application -Source $EventSource -EntryType $Level -EventId $EventID -Message $Message -ErrorAction SilentlyContinue
    } catch {}
}

# ────────────────────── NOTIFICATIONS ──────────────────────
function Notify($Text) {
    if ($Config.EnableTelegram -and $Config.TelegramToken) {
        $body = @{chat_id = $Config.TelegramChatID; text = $Text; parse_mode = "HTML"}
        try {
            Invoke-RestMethod -Uri "https://api.telegram.org/bot$($Config.TelegramToken)/sendMessage" -Method Post -Body $body -TimeoutSec 10 | Out-Null
        } catch {}
    }
    if ($Config.EnableWhatsApp -and $Config.TwilioSID -and $Config.TwilioToken) {
        $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Config.TwilioSID):$($Config.TwilioToken)"))
        $body = @{From = "whatsapp:$($Config.TwilioFrom)"; To = "whatsapp:$($Config.TwilioTo)"; Body = $Text}
        try {
            Invoke-RestMethod "https://api.twilio.com/2010-04-01/Accounts/$($Config.TwilioSID)/Messages.json" `
                -Method Post -Headers @{Authorization = "Basic $auth"} -Body $body -ContentType "application/x-www-form-urlencoded" | Out-Null
        } catch {}
    }
}

# ────────────────────── AUTO-UPDATE FROM config.json URL ──────────────────────
$global:LastUpdateCheck = [DateTime]::MinValue
function AutoUpdate {
    if ((Get-Date) - $global:LastUpdateCheck -lt [TimeSpan]::FromSeconds($Config.AutoUpdateCheck)) { return }
    $global:LastUpdateCheck = Get-Date
    try {
        $latest = Invoke-WebRequest $Config.ScriptUrl -UseBasicParsing -TimeoutSec 15
        $current = Get-Content $MyInvocation.MyCommand.Path -Raw
        if ($latest.Content.Trim() -ne $current.Trim()) {
            Log "Updating AutoSSH-Ultimate.ps1 from $($Config.ScriptUrl)..." "Information" 1001
            Notify "AutoSSH Ultimate is updating itself on $(hostname)"
            $latest.Content | Out-File "$($MyInvocation.MyCommand.Path).new" -Encoding utf8
            Move-Item "$($MyInvocation.MyCommand.Path).new" $MyInvocation.MyCommand.Path -Force
            Restart-Service AutoSSH-Ultimate -Force
        }
    } catch {}
}

# ────────────────────── WEB DASHBOARD (runs in background job) ──────────────────────
$global:HttpListener = $null
if ($Config.EnableWeb) {
    $global:HttpListener = New-Object System.Net.HttpListener
    $global:HttpListener.Prefixes.Add("http://localhost:$($Config.WebPort)/")
    $global:HttpListener.Start()

    $webJob = {
        param($listener, $logFile)
        while ($listener.IsListening) {
            try {
                $context = $listener.GetContext()
                $req = $context.Request
                $resp = $context.Response
                if ($req.Url.LocalPath -eq "/api/status") {
                    $procs = Get-Process ssh -ErrorAction SilentlyContinue | Select-Object Id, StartTime, Path
                    $json = $procs | ConvertTo-Json
                    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                    $resp.ContentType = "application/json"
                    $resp.OutputStream.Write($bytes,0,$bytes.Length)
                } else {
                    $log = Get-Content $logFile -Tail 60 -ErrorAction SilentlyContinue | Out-String
                    $html = "<pre style='font-family:Consolas;background:#000;color:#0f0;padding:20px;'>AutoSSH Ultimate – $(hostname)`n`n$log</pre><hr><small>Refresh: 15s | <a href='/api/status'>JSON API</a></small>"
                    $bytes = [Text.Encoding]::UTF8.GetBytes($html)
                    $resp.OutputStream.Write($bytes,0,$bytes.Length)
                }
                $resp.Close()
            } catch {}
        }
    }
    Start-Job -ScriptBlock $webJob -ArgumentList $global:HttpListener, $Config.LogFile | Out-Null
}

# ────────────────────── CONFIG RELOAD ON AutoSSH.tsv CHANGE ──────────────────────
$global:ConfigChanged = $true
$Watcher = New-Object IO.FileSystemWatcher $ScriptPath, "AutoSSH.tsv"
$Watcher.NotifyFilter = "LastWrite"
$Watcher.EnableRaisingEvents = $true
Register-ObjectEvent $Watcher Changed -Action { $global:ConfigChanged = $true } > $null

# ────────────────────── LOAD TUNNELS FROM TSV ──────────────────────
function Load-Tunnels {
    if (-not $global:ConfigChanged) { return $global:Tunnels }
    $global:ConfigChanged = $false

    $list = @()
    if (-not (Test-Path $Config.ConfigFile)) {
        Log "AutoSSH.tsv not found!" "Error"
        return $list
    }

    Get-Content $Config.ConfigFile -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#")) { return }
        $f = $line -split "\t" | ForEach-Object Trim
        if ($f.Count -lt 8) { return }

        $extra = @{}
        if ($f.Count -ge 9) {
            ($f[8..($f.Count-1)] -join " ") -split "\s+" | Where-Object {$_ -match "(.+?)=(.*)"} | ForEach-Object {
                $extra[$Matches[1]] = $Matches[2]
            }
        }

        $list += [PSCustomObject]@{
            Type       = $f[0].ToUpper()
            LocalPort  = $f[1]
            TargetHost = $f[2]
            TargetPort = $f[3]
            SshHost    = $f[4]
            SshPort    = $f[5]
            SshUser    = $f[6]
            SshKey     = $f[7]
            Comment    = ($f[8..($f.Count-1)] -join " " -replace '^\S+\s*','').Trim()
            Extra      = $extra
        }
    }
    $global:Tunnels = $list
    Log "Reloaded $($list.Count) tunnel(s)" "Information"
    return $list
}

# ────────────────────── MAIN LOOP ──────────────────────
$global:Tunnels = @()
$Processes = @{}
$LastHealth = @{}
$LastPortCheck = @{}

Log "AutoSSH Ultimate started – Dashboard: http://localhost:$($Config.WebPort)" "Information" 1000
Notify "AutoSSH Ultimate started on $(hostname)"

while ($true) {
    AutoUpdate
    $tunnels = Load-Tunnels

    foreach ($t in $tunnels) {
        $key = "$($t.Type)-$($t.SshHost):$($t.SshPort)-$($t.SshUser)-$($t.LocalPort)"
        $proc = $Processes[$key]
        $now = Get-Date
        $restart = $false
        $reason = ""

        # Health checks
        if (-not $proc -or $proc.HasExited) {
            $reason = "Process died"
            $restart = $true
        }
        elseif (($LastHealth[$key] -eq $null) -or ($now - $LastHealth[$key]).TotalSeconds -gt $Config.HealthCheckInterval) {
            $control = "$($Config.ControlDir)\ssh-%h-%p-%r" -replace '%h',$t.SshHost -replace '%p',$t.SshPort -replace '%r',$t.SshUser
            $null = ssh -o ControlPath="$control" -O check "$($t.SshUser)@$($t.SshHost)" 2>$null
            if ($LASTEXITCODE -ne 0) { $reason = "Control socket frozen"; $restart = $true } else { $LastHealth[$key] = $now }
        }
        elseif (($LastPortCheck[$key] -eq $null) -or ($now - $LastPortCheck[$key]).TotalSeconds -gt $Config.PortCheckInterval) {
            $ok = Test-NetConnection 127.0.0.1 -Port $t.LocalPort -InformationLevel Quiet -WarningAction SilentlyContinue
            if (-not $ok) { $reason = "Port not listening"; $restart = $true } else { $LastPortCheck[$key] = $now }
        }

        if ($restart) {
            Log "$reason → $($t.Comment)" "Warning" 2000
            Notify "<b>TUNNEL DOWN</b>`n$(hostname)`n$($t.Comment)`nReason: $reason"

            if ($proc) { try{$proc.Kill()}catch{} }
            $Processes.Remove($key) | Out-Null
            Start-Sleep -Seconds $Config.RestartDelay

            # Build safe argument array
            $a = New-Object 'System.Collections.Generic.List[string]'
            $a.Add("-N")
            $a.Add((if($t.Type -eq 'R'){'-R'}else{'-L'}))
            $a.Add("$($t.LocalPort):$($t.TargetHost):$($t.TargetPort)")

            $control = "$($Config.ControlDir)\ssh-%h-%p-%r" -replace '%h',$t.SshHost -replace '%p',$t.SshPort -replace '%r',$t.SshUser
            $a.Add("-o"); $a.Add("ControlMaster=auto")
            $a.Add("-o"); $a.Add("ControlPath=$control")
            $a.Add("-o"); $a.Add("ControlPersist=10m")
            $a.Add("-o"); $a.Add("BatchMode=yes")
            $a.Add("-o"); $a.Add("IdentitiesOnly=yes")
            $a.Add("-o"); $a.Add("StrictHostKeyChecking=$($Config.StrictHostKeyChecking)")

            $int = if($t.Extra.ServerAliveInterval){$t.Extra.ServerAliveInterval}else{$Config.ServerAliveInterval}
            $cnt = if($t.Extra.ServerAliveCountMax){$t.Extra.ServerAliveCountMax}else{$Config.ServerAliveCountMax}
            $a.Add("-o"); $a.Add("ServerAliveInterval=$int")
            $a.Add("-o"); $a.Add("ServerAliveCountMax=$cnt")
            $a.Add("-o"); $a.Add("ExitOnForwardFailure=yes")

            foreach ($k in $t.Extra.Keys) {
                if ($k -notin "ServerAliveInterval","ServerAliveCountMax") {
                    $a.Add("-o"); $a.Add("$k=$($t.Extra[$k])")
                }
            }

            $a.Add("-p"); $a.Add($t.SshPort)
            $a.Add("-i"); $a.Add($t.SshKey)
            $a.Add("$($t.SshUser)@$($t.SshHost)")

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "ssh.exe"
            $psi.Arguments = $a -join " "
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true

            try {
                $newProc = [System.Diagnostics.Process]::Start($psi)
                $Processes[$key] = $newProc
                Log "Started PID $($newProc.Id) → $($t.Comment)" "Information"
                Notify "Tunnel UP again: $($t.Comment)"
            } catch {
                Log "START FAILED: $($_.Exception.Message)" "Error"
            }
        }
    }
    Start-Sleep -Seconds $Config.CheckInterval
}
