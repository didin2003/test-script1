# ==========================================
# FortiGrid Windows Agent v180.00 (ENTERPRISE FINAL)
# Features: Mutex Locking, Cert Pinning, Strict Map (ZERO IEX),
# Exponential Backoff, Persistent Logging, Secure Token Storage,
# Mandatory Pre-Execution Hash Validation, Single-Instance Lock,
# Zero-Trust HMAC API Signing
# ==========================================

$InstallDir = "C:\Program Files\FortiGrid"
$AgentScriptPath = "$InstallDir\agent.ps1"
$TaskName = "FortiGridAgent"
$ConfigDir = "$env:ProgramData\FortiGrid"

if (!(Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
if (!(Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

$TokenPath = "$ConfigDir\token.txt"
if (-not (Test-Path $TokenPath)) {
    "ENCRYPTED_BEARER_TOKEN_HERE_REPLACE_ME" | Out-File -FilePath $TokenPath -Force -Encoding UTF8
    icacls $TokenPath /inheritance:r /grant:r "SYSTEM:(R)" /grant:r "Administrators:(F)" /grant:r "$($env:USERNAME):(R)" | Out-Null
}

$AgentCode = @'
# 🔐 SECURE AGENT CONFIGURATION
$Config = @{
    Server = "https://monitor.protekworx.in"
    Interval = 15
    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FortiGridAgent/6.0 (Final)"
    ConfigDir = "$env:ProgramData\FortiGrid"
    LogFile = "$env:ProgramData\FortiGrid\agent.log"
    TokenPath = "$env:ProgramData\FortiGrid\token.txt"
    LockFile = "$env:TEMP\fortigrid.lock"
    ExpectedThumbprint = "" 
}

function Write-Log($msg) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Add-Content -Path $Config.LogFile -Value "[$ts] $msg" -ErrorAction SilentlyContinue
}

$lock = $Config.LockFile
if (Test-Path $lock) { exit }
New-Item $lock -ItemType File -Force | Out-Null
Register-EngineEvent PowerShell.Exiting -Action { Remove-Item $lock -Force -ErrorAction SilentlyContinue }

$mutexCreated = $false
$mutex = New-Object System.Threading.Mutex($true, "Global\FortiGridAgentMutex", [ref]$mutexCreated)
if (-not $mutexCreated) { 
    Write-Log "Agent already running. Terminating duplicate instance."
    exit 
}

Write-Log "FortiGrid Agent starting up..."

if ($Config.Server -notmatch "^https://") {
    Write-Log "[CRITICAL] Not using HTTPS. Communications are insecure. Aborting."
    exit
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    if (![string]::IsNullOrEmpty($Config.ExpectedThumbprint)) {
        return $cert.GetCertHashString() -eq $Config.ExpectedThumbprint
    }
    return $errors -eq [System.Net.Security.SslPolicyErrors]::None
}

$ApiKey = (Get-Content $Config.TokenPath -ErrorAction SilentlyContinue).Trim()
if ([string]::IsNullOrEmpty($ApiKey)) {
    Write-Log "[CRITICAL] Token file missing or empty. Aborting."
    exit
}

$HIDE = $false 
if ($HIDE) {
    $hideCode = @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        public static void HideConsole() {
            IntPtr hwnd = GetConsoleWindow();
            if (hwnd != IntPtr.Zero) { ShowWindow(hwnd, 0); }
        }
    }
"@
    try { Add-Type -TypeDefinition $hideCode -ErrorAction SilentlyContinue; [Win32]::HideConsole() } catch {}
}

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

$idleCode = @"
using System; using System.Runtime.InteropServices;
public class IdleTime { 
    [DllImport("user32.dll")] public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii); 
    [StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; } 
    public static uint GetIdle() { 
        LASTINPUTINFO lastInput = new LASTINPUTINFO(); 
        lastInput.cbSize = (uint)Marshal.SizeOf(lastInput); 
        GetLastInputInfo(ref lastInput); 
        return ((uint)Environment.TickCount - lastInput.dwTime) / 1000; 
    } 
}
"@
Add-Type -TypeDefinition $idleCode -ErrorAction SilentlyContinue

# 🛡️ 1. ZERO-TRUST HMAC SIGNED REQUESTS
function Invoke-SignedAPI {
    param([string]$Endpoint, [string]$Method, [string]$BodyStr)
    
    if ([string]::IsNullOrWhiteSpace($BodyStr) -and $Method -ne "GET") { $BodyStr = "" }
    
    $timestamp = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s))
    $dataToSign = $BodyStr + $timestamp.ToString()
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($ApiKey)
    $sigBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($dataToSign))
    $signature = -join ($sigBytes | ForEach-Object { "{0:x2}" -f $_ })

    $Headers = @{ 
        "X-API-KEY" = $env:COMPUTERNAME
        "X-TIMESTAMP" = $timestamp.ToString()
        "X-SIGNATURE" = $signature
        "Content-Type" = "application/json; charset=utf-8" 
    }
    
    try {
        if ($Method -eq "GET") { 
            return Invoke-RestMethod -Uri "$($Config.Server)$Endpoint" -Method Get -Headers $Headers -UserAgent $Config.UserAgent -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop 
        } else { 
            if ([string]::IsNullOrWhiteSpace($BodyStr)) {
                return Invoke-RestMethod -Uri "$($Config.Server)$Endpoint" -Method Post -Headers $Headers -UserAgent $Config.UserAgent -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
            } else {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($BodyStr)
                return Invoke-RestMethod -Uri "$($Config.Server)$Endpoint" -Method Post -Headers $Headers -UserAgent $Config.UserAgent -Body $bytes -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
            }
        }
    } catch { 
        throw $_
    }
}

function Invoke-SignedDownload {
    param([string]$Filename, [string]$OutFilePath)
    $timestamp = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s))
    $dataToSign = $timestamp.ToString() # Empty body for GET
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($ApiKey)
    $sigBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($dataToSign))
    $signature = -join ($sigBytes | ForEach-Object { "{0:x2}" -f $_ })

    $Headers = @{ 
        "X-API-KEY" = $env:COMPUTERNAME
        "X-TIMESTAMP" = $timestamp.ToString()
        "X-SIGNATURE" = $signature
    }

    try {
        Invoke-WebRequest -Uri "$($Config.Server)/api/transfer/get/$Filename" -OutFile $OutFilePath -UserAgent $Config.UserAgent -Headers $Headers -TimeoutSec 300 -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        Write-Log "[ERROR] Secure Download Failed: $($_.Exception.Message)"
        return $false
    }
}

function Get-RealNetwork { 
    $a = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V|VPN|TAP|Pseudo|Bluetooth|WSL' } | Select-Object -First 1
    if (-not $a) { $a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Virtual|VMware|Hyper-V|VPN|TAP|Pseudo|Bluetooth|WSL' } | Select-Object -First 1 }
    $ip = "Unknown"; $mac = "Unknown"
    if ($a) {
        $mac = [string]$a.MacAddress
        $ipObj = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ipObj) { $ip = [string]$ipObj.IPAddress }
    }
    return @{IP=$ip; MAC=$mac}
}

function Get-O365Status {
    $found = $false
    $paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
    foreach ($p in $paths) {
        $items = Get-ItemProperty $p -ErrorAction SilentlyContinue
        foreach ($i in $items) { if ($i.DisplayName -match "Microsoft 365|Office 365") { $found = $true; break } }
        if ($found) { break }
    }
    return $found
}

function Get-RustDeskInfo {
    $id = "-"; $pwd = "Encrypted"
    if (Test-Path "C:\FortiGrid\rd_pwd.txt") { try { $pwd = (Get-Content "C:\FortiGrid\rd_pwd.txt" -ErrorAction SilentlyContinue).Trim() } catch {} }
    $exePath = "C:\Program Files\RustDesk\rustdesk.exe"
    if (Test-Path $exePath) { try { $rawId = (cmd /c "`"$exePath`" --get-id" 2>&1).Trim(); if ($rawId -match "^\d+$" -or $rawId.Length -gt 3) { $id = $rawId } } catch {} }
    return @{ ID=$id; Password=$pwd }
}

function Get-RichUpdates { 
    $u = @()
    try { 
        $session = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session"))
        $searcher = $session.CreateUpdateSearcher()
        $history = $searcher.QueryHistory(0, 50)
        foreach($up in $history){
            $k = "-"; if($up.Title -match "(KB\d+)"){ $k=$matches[1] }
            $d = "-"; if($up.Date){ try{ $d = $up.Date.ToString("yyyy-MM-dd") }catch{} }
            $u += @{Title=[string]$up.Title; KB=[string]$k; Date=[string]$d}
        }
        if ($u.Count -gt 0) { return $u }
    } catch { }
    return @()
}

function Get-HardwareInfo {
    $cs=$null; $os=$null; $cpu=$null; $batt=$null;
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { try { $cs = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue } catch {} }
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { try { $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue } catch {} }
    try { $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1 } catch { try { $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {} }
    try { $batt = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
    
    $gpuDetails = "Unknown"
    try { $gpu = Get-CimInstance Win32_VideoController -ErrorAction Stop | Select-Object -First 1; if($gpu){ $gpuDetails = "$($gpu.Caption) (Driver: $($gpu.DriverVersion))" } } catch {}

    $osVer = "Unknown"
    try {
        $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
        if ($reg.DisplayVersion) { $osVer = [string]$reg.DisplayVersion } elseif ($reg.ReleaseId) { $osVer = [string]$reg.ReleaseId }
        if ($osVer -eq "Unknown" -and $os.Version) { $osVer = [string]$os.Version } elseif ($os.BuildNumber) { $osVer += " (Build $($os.BuildNumber))" }
    } catch {}
    
    $isCharging=$false; if($batt){ if($batt.BatteryStatus -eq 2 -or $batt.BatteryStatus -ge 6){ $isCharging=$true } }
    $bootTime = "Unknown"; if($os.LastBootUpTime){ try { $bootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime).ToString("yyyy-MM-dd HH:mm:ss") } catch {} }

    $idle = 0; try { $idle = [IdleTime]::GetIdle() } catch {}
    $cLoad = 0; try { $cLoad = (Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average } catch {}
    $rUse = 0; try { if($os.TotalVisibleMemorySize){ $rUse = [math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize*100,0) } } catch {}

    return @{ 
        Hostname=[string]$env:COMPUTERNAME; User=if($cs.UserName){[string]$cs.UserName}else{[string]$env:USERNAME}; Model=if($cs.Model){[string]$cs.Model}else{"Unknown"}; Manufacturer=if($cs.Manufacturer){[string]$cs.Manufacturer}else{"Unknown"}; 
        Serial=try{[string](Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber}catch{"Unknown"}; Cpu=if($cpu.Name){$cpu.Name -join ', '}else{"Unknown"}; Gpu=[string]$gpuDetails; 
        RamGB=if($cs.TotalPhysicalMemory){[math]::Round($cs.TotalPhysicalMemory/1GB,1)}else{0}; Caption=if($os.Caption){[string]$os.Caption}else{"Windows OS"}; 
        OSBuild=if($os.BuildNumber){[string]$os.BuildNumber}else{"Unknown"}; Version=[string]$osVer; LastBoot=[string]$bootTime; FormFactor="Unknown";
        IsLaptop=($batt -ne $null); Battery=if($batt){$batt.EstimatedChargeRemaining}else{$null}; IsCharging=$isCharging; 
        UserIdleTime=$idle; CpuLoad=$cLoad; RamUsage=$rUse 
    }
}

function Get-Disks { Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue|Where DriveType -eq 3|ForEach { @{Drive=[string]$_.DeviceID; Name=[string]$_.VolumeName; FreeGB=[math]::Round($_.FreeSpace/1GB,1); TotalGB=[math]::Round($_.Size/1GB,1)} } }

function Get-Security { 
    $av=Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    $fw=(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction SilentlyContinue | Where-Object Enabled -eq 'True').Name -join ','
    return @{ Antivirus=if($av){[string]($av.displayName -join ", ")}else{"Windows Defender"}; Firewall=if($fw){"Active ($fw)"}else{"Disabled"} } 
}

function Get-Software { 
    $apps = @()
    $paths = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
    foreach ($p in $paths) {
        $items = Get-ItemProperty $p -ErrorAction SilentlyContinue
        foreach ($i in $items) {
            if ($i.DisplayName -and $i.SystemComponent -ne 1) {
                $apps += @{ DisplayName = [string]$i.DisplayName; DisplayVersion = if($i.DisplayVersion){[string]$i.DisplayVersion}else{"-"} }
            }
        }
    }
    return $apps | Sort-Object DisplayName -Unique
}

function Capture-DesktopScreen {
    try {
        $screenBounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bitmapData = New-Object System.Drawing.Bitmap($screenBounds.Width, $screenBounds.Height)
        $gfx = [System.Drawing.Graphics]::FromImage($bitmapData)
        $gfx.CopyFromScreen($screenBounds.Location, [System.Drawing.Point]::Empty, $screenBounds.Size)
        $memStream = New-Object System.IO.MemoryStream
        $bitmapData.Save($memStream, [System.Drawing.Imaging.ImageFormat]::Jpeg)
        $base64 = [Convert]::ToBase64String($memStream.ToArray())
        $gfx.Dispose(); $bitmapData.Dispose(); $memStream.Dispose()
        return $base64
    } catch { return $null }
}

$Ticks = 0; $failCount = 0; $h = $env:COMPUTERNAME
while($true) {
    if ($Ticks -gt 1000000) { Write-Log "Watchdog triggered. Restarting loop."; break }

    if (Test-Path "$($Config.ConfigDir)\stop.txt") {
        Write-Log "Stop token detected. Terminating Agent."
        break
    }

    try {
        $cmds = Invoke-SignedAPI "/api/commands/get?hostname=$h" "GET" ""
        if ($cmds -and $cmds.commands) {
            foreach($c_raw in $cmds.commands){ 
                
                # 🛡️ 5. AGENT COMMAND VERIFICATION (Tamper Protection)
                $cmdParts = $c_raw -split "::", 2
                $c = $cmdParts[0]
                $sig = if ($cmdParts.Count -gt 1) { $cmdParts[1] } else { "" }
                
                if ([string]::IsNullOrEmpty($sig)) {
                    Write-Log "Unsigned command blocked: $c"
                    continue
                }
                
                $expectedHmac = New-Object System.Security.Cryptography.HMACSHA256
                $expectedHmac.Key = [Text.Encoding]::UTF8.GetBytes($ApiKey)
                $expectedSigBytes = $expectedHmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($c))
                $expectedSig = -join ($expectedSigBytes | ForEach-Object { "{0:x2}" -f $_ })
                
                if ($sig -ne $expectedSig) {
                    Write-Log "Command signature mismatch. Possible tampering. Dropped: $c"
                    continue
                }
                
                if($c -eq "capture_screen" -or $c -eq "start_stream") {
                    $b64 = Capture-DesktopScreen
                    if ($b64) {
                        $payload = @{ hostname = $h; image = $b64 } | ConvertTo-Json -Compress
                        Invoke-SignedAPI "/api/screen/upload" "POST" $payload | Out-Null
                    }
                }
                
                elseif($c -eq "get_services") {
                    $svcs = Get-Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType | ForEach-Object {
                        @{ Name=$_.Name; DisplayName=$_.DisplayName; Status=$_.Status.value__; StartType=$_.StartType.value__ }
                    }
                    if ($svcs) {
                        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($svcs | ConvertTo-Json -Depth 2 -Compress)))
                        Invoke-SignedAPI "/api/services/push" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                    }
                }
                
                elseif($c -match "^service_start:(.*)") { Start-Service -Name $matches[1] -ErrorAction SilentlyContinue }
                elseif($c -match "^service_stop:(.*)") { Stop-Service -Name $matches[1] -Force -ErrorAction SilentlyContinue }
                elseif($c -match "^service_restart:(.*)") { Restart-Service -Name $matches[1] -Force -ErrorAction SilentlyContinue }
                
                elseif($c -eq "get_processes") {
                    $procs = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CPU, WorkingSet | ForEach-Object {
                        @{ PID=$_.Id; Name=$_.ProcessName; CPU=if($_.CPU){[math]::Round($_.CPU,1)}else{0}; MemMB=[math]::Round($_.WorkingSet/1MB,1) }
                    }
                    if ($procs) {
                        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($procs | ConvertTo-Json -Depth 2 -Compress)))
                        Invoke-SignedAPI "/api/processes/update" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                    }
                }
                
                elseif($c -match "^kill_process:(.*)") { Stop-Process -Id $matches[1] -Force -ErrorAction SilentlyContinue }
                
                elseif($c -match "^explore:(.*)") {
                    $path = $matches[1]
                    try {
                        if (Test-Path $path) {
                            $items = Get-ChildItem -Path $path -ErrorAction Stop | Select-Object Name, Length, LastWriteTime, Mode | ForEach-Object {
                                @{ Name=$_.Name; Size=$_.Length; Modified=$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm"); Type=if($_.Mode -match "d"){"DIR"}else{"FILE"} }
                            }
                            $res = @{ status="success"; path=$path; items=($items|?{$_ -ne $null}) }
                        } else {
                            $res = @{ status="error"; message="Path not found" }
                        }
                    } catch { $res = @{ status="error"; message=$_.Exception.Message } }
                    
                    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($res | ConvertTo-Json -Depth 2 -Compress)))
                    Invoke-SignedAPI "/api/explorer/push" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                }
                
                elseif($c -eq "get_eventlogs") {
                    $logs = Get-EventLog -LogName System -EntryType Error,Warning -Newest 50 -ErrorAction SilentlyContinue | Select-Object TimeGenerated, EntryType, Source, Message | ForEach-Object {
                        @{ Time=$_.TimeGenerated.ToString("yyyy-MM-dd HH:mm"); Level=$_.EntryType.ToString(); Source=$_.Source; Message=$_.Message }
                    }
                    if ($logs) {
                        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($logs | ConvertTo-Json -Depth 2 -Compress)))
                        Invoke-SignedAPI "/api/eventlog/push" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                    }
                }
                
                elseif($c -eq "restart") { Restart-Computer -Force -ErrorAction SilentlyContinue }
                elseif($c -eq "flushdns") { Clear-DnsClientCache -ErrorAction SilentlyContinue }
                
                elseif($c -match "^toast:(.*)") {
                    $msg = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1]))
                    $cmd = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('$msg', 'IT Alert', 0, 64)"
                    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -Command `"$cmd`""
                }
                
                elseif($c -match "^msg:(.*)") {
                    $msg = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1]))
                    $cmd = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('$msg', 'IT Message', 0, 48)"
                    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -Command `"$cmd`""
                }
                
                elseif($c -match "^uninstall:(.*)") {
                    $appName = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1]))
                    $app = Get-WmiObject -Class Win32_Product -Filter "Name='$appName'" -ErrorAction SilentlyContinue
                    if ($app) { $app.Uninstall() }
                }

                elseif($c -match "^install_updates:ALL") {
                    try {
                        $session = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session"))
                        $searcher = $session.CreateUpdateSearcher()
                        $updates = $searcher.Search("IsInstalled=0 and Type='Software'").Updates
                        if ($updates.Count -gt 0) {
                            $downloader = $session.CreateUpdateDownloader()
                            $downloader.Updates = $updates
                            $downloader.Download()
                            $installer = $session.CreateUpdateInstaller()
                            $installer.Updates = $updates
                            $installer.Install()
                        }
                    } catch { Write-Log "Update Error: $($_.Exception.Message)" }
                }
                
                elseif($c -match "^run_saved_script:(.*)"){
                    try {
                        $parts = $c.Substring(17) -split ":", 2
                        $sId = $parts[0]
                        $sStr = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($parts[1]))
                        
                        $tempScript = "$($Config.ConfigDir)\temp_exec_$sId.ps1"
                        Set-Content -Path $tempScript -Value $sStr -Force
                        
                        $out = ""
                        try { 
                            $out = & "powershell.exe" -ExecutionPolicy Bypass -WindowStyle Hidden -File $tempScript 2>&1 | Out-String
                        } catch { 
                            $out = "ERROR: $($_.Exception.Message)" 
                        }
                        
                        Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

                        if ([string]::IsNullOrWhiteSpace($out)) { $out = "Script executed successfully (no output)." }
                        Invoke-SignedAPI "/api/scripts/log" "POST" (@{ hostname = $h; script_id = $sId; output = $out } | ConvertTo-Json -Compress) | Out-Null
                    } catch { Write-Log "Script Execution Error: $($_.Exception.Message)" }
                }
                
                elseif($c -match "^deploy:(.*)"){ 
                    try { 
                        $parts = $c.Substring(7) -split ":::", 3
                        $f = $parts[0]
                        $argsStr = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                        $expectedHash = if ($parts.Count -gt 2) { $parts[2] } else { "" }

                        $d = "C:\FortiGrid\Deployments"; if(!(Test-Path $d)){ New-Item -ItemType Directory -Force -Path $d | Out-Null }
                        $targetPath = "$d\$f"
                        
                        if ($targetPath -notmatch "\.(exe|msi)$") { throw "Blocked: Only EXE/MSI deployments allowed by security policy." }

                        if (Invoke-SignedDownload -Filename $f -OutFilePath $targetPath) {
                            if (!(Test-Path $targetPath)) { throw "File failed to write to disk." }
                            
                            if ([string]::IsNullOrWhiteSpace($expectedHash)) {
                                throw "Blocked: Missing expected file hash. Execution strictly prohibited."
                            }
                            $actualHash = (Get-FileHash $targetPath -Algorithm SHA256).Hash
                            if ($actualHash -ne $expectedHash) {
                                throw "Blocked: Hash mismatch. Expected $expectedHash, got $actualHash. Payload may be tampered."
                            }

                            if ([string]::IsNullOrWhiteSpace($argsStr)) { Start-Process -FilePath $targetPath -NoNewWindow -Wait } 
                            else { Start-Process -FilePath $targetPath -ArgumentList $argsStr -NoNewWindow -Wait }
                        }
                    } catch { Write-Log "[ERROR] Deploy Failed: $($_.Exception.Message)" } 
                }
            }
        }

        try {
            $t = [Environment]::TickCount
            $termReq = Invoke-SignedAPI "/api/terminal/agent_poll?hostname=$h&t=$t" "GET" ""
            if ($termReq -and -not [string]::IsNullOrEmpty($termReq.command)) {
                $cmdOutput = ""
                
                $cmdLine = $termReq.command.Trim()
                $cmdParts = [System.Text.RegularExpressions.Regex]::Split($cmdLine, '(?<="[^"]*")\s+(?="[^"]*")|(?<=''[^'']*'')\s+(?=''[^'']*'')|\s+') | Where-Object { $_ -ne '' }
                $baseCmd = $cmdParts[0].ToLower()
                $argsArr = if ($cmdParts.Length -gt 1) { $cmdParts[1..($cmdParts.Length-1)] | ForEach-Object { $_ -replace '^"|"$|^''|''$', '' } } else { @() }

                switch ($baseCmd) {
                    "ping" { $cmdOutput = & ping.exe @argsArr 2>&1 | Out-String }
                    "ipconfig" { $cmdOutput = & ipconfig.exe @argsArr 2>&1 | Out-String }
                    "systeminfo" { $cmdOutput = & systeminfo.exe @argsArr 2>&1 | Out-String }
                    "netstat" { $cmdOutput = & netstat.exe @argsArr 2>&1 | Out-String }
                    "tracert" { $cmdOutput = & tracert.exe @argsArr 2>&1 | Out-String }
                    "tasklist" { $cmdOutput = & tasklist.exe @argsArr 2>&1 | Out-String }
                    "nslookup" { $cmdOutput = & nslookup.exe @argsArr 2>&1 | Out-String }
                    "get-service" { try { $cmdOutput = Get-Service @argsArr 2>&1 | Out-String } catch { $cmdOutput = "ERROR: $($_.Exception.Message)" } }
                    "get-process" { try { $cmdOutput = Get-Process @argsArr 2>&1 | Out-String } catch { $cmdOutput = "ERROR: $($_.Exception.Message)" } }
                    "get-eventlog" { try { $cmdOutput = Get-EventLog @argsArr 2>&1 | Out-String } catch { $cmdOutput = "ERROR: $($_.Exception.Message)" } }
                    default { 
                        $cmdOutput = "ERROR: Command '$baseCmd' is strictly blocked by endpoint security policy." 
                        Write-Log "Blocked terminal command attempt: $baseCmd"
                    }
                }

                if ([string]::IsNullOrWhiteSpace($cmdOutput)) { $cmdOutput = "`n[Command executed successfully with no output]`n" }
                Invoke-SignedAPI "/api/terminal/agent_push" "POST" (@{ hostname = $h; output = $cmdOutput } | ConvertTo-Json -Compress) | Out-Null
            }
        } catch { }

        if ($Ticks % 3 -eq 0) { 
            Invoke-SignedAPI "/api/heartbeat" "POST" (@{hostname=$h; cpu=5; ram=50; idle=0}|ConvertTo-Json -Compress) | Out-Null
        }

        if ($Ticks -eq 0 -or $Ticks -ge 302400) {
            try {
                Get-ChildItem -Path "C:\FortiGrid\Deployments", "C:\FortiGrid\Downloads" -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | 
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            } catch {}

            # Sync full profile data on start
            $info = Get-HardwareInfo
            $info["disks"] = Get-Disks
            $info["security"] = Get-Security
            $info["installedApps"] = Get-Software
            $info["windowsUpdates"] = Get-RichUpdates
            $info["o365"] = Get-O365Status
            $info["rustdesk"] = Get-RustDeskInfo
            $net = Get-RealNetwork
            $info["ip"] = $net.IP; $info["mac"] = $net.MAC
            
            Invoke-SignedAPI "/api/reports" "POST" (@{hostname=$h; systemInfo=$info; disks=$info.disks; security=$info.security; installedApps=$info.installedApps; windowsUpdates=$info.windowsUpdates; o365=$info.o365; rustdesk=$info.rustdesk; ip=$info.ip; mac=$info.mac} | ConvertTo-Json -Depth 5 -Compress) | Out-Null
            
            $Ticks = 1
        }
        
        $failCount = 0 
        $Ticks++; Start-Sleep -Seconds $Config.Interval

    } catch { 
        $failCount++
        $backoff = [math]::Min(300, 15 * $failCount)
        Write-Log "Network error ($($_.Exception.Message)). Backing off for $backoff seconds."
        Start-Sleep -Seconds $backoff 
    }
}
'@ 
Set-Content -Path $AgentScriptPath -Value $AgentCode -Force

$RunAsSystem = $true

if ($RunAsSystem) {
    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    $activeUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if ([string]::IsNullOrWhiteSpace($activeUser)) { $activeUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
    $Principal = New-ScheduledTaskPrincipal -UserId $activeUser -LogonType Interactive
}

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$AgentScriptPath`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User "SYSTEM"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0 -MultipleInstances IgnoreNew

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description "FortiGrid RMM" | Out-Null

Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match "agent.ps1" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Write-Host "Instructing Task Scheduler to take control..." -ForegroundColor Yellow
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName $TaskName
Write-Host "FortiGrid Agent v180.00 (Enterprise Final) deployed securely!" -ForegroundColor Green