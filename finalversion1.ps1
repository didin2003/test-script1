# ==========================================
# FortiGrid Agent - ENTERPRISE DIAGNOSTIC MODE
# Features: Split-Key HMAC, Strict TOFU Registration, 
# Nonce Anti-Replay, PS7 WinForms Fallback
# ==========================================

$ConfigDir = "$env:ProgramData\FortiGrid"
if (!(Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }

$TokenPath = "$ConfigDir\token.txt"

if (-not (Test-Path $TokenPath)) {
    $bytes = New-Object Byte[] 32
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($bytes)
    $rawToken = [Convert]::ToBase64String($bytes) -replace "[+=/]", ""
    $secure = ConvertTo-SecureString $rawToken -AsPlainText -Force
    $secure | ConvertFrom-SecureString | Out-File -FilePath $TokenPath -Force
}

# ✅ FIX 2 & 3: Added RegisterKey for TOFU and CommandSecret for split-key validation
$Config = @{
    Server = "https://monitor.protekworx.in"
    Interval = 10
    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FortiGridAgent/7.0 (Diag)"
    RegisterKey = "e27aaf2ffda5870bf8f4c94798764e47"
    CommandSecret = "03b122466b3dcb53627f43fd44cddc4d4fd3d2ba33b4c1a45936d664db49f598"
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "FortiGrid Agent - DIAGNOSTIC MODE STARTING" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

try {
    $encryptedToken = Get-Content $TokenPath -ErrorAction Stop
    $secureString = ConvertTo-SecureString $encryptedToken -ErrorAction Stop
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    Write-Host "[OK] Token loaded successfully." -ForegroundColor Green
} catch { Write-Host "[CRITICAL] Token missing." -ForegroundColor Red; exit }

try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop } catch { [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null }
try { Add-Type -AssemblyName System.Drawing -ErrorAction Stop } catch { [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null }

function Invoke-SignedAPI {
    param([string]$Endpoint, [string]$Method, [string]$BodyStr)
    if ([string]::IsNullOrWhiteSpace($BodyStr) -and $Method -ne "GET") { $BodyStr = "" }
    
    $timestamp = [int][double]::Parse((Get-Date (Get-Date).ToUniversalTime() -UFormat %s))
    $nonce = [guid]::NewGuid().ToString()
    
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($BodyStr)
    $timeNonceBytes = [System.Text.Encoding]::UTF8.GetBytes($timestamp.ToString() + $nonce)
    
    $dataToSignBytes = New-Object Byte[] ($bodyBytes.Length + $timeNonceBytes.Length)
    [System.Array]::Copy($bodyBytes, 0, $dataToSignBytes, 0, $bodyBytes.Length)
    [System.Array]::Copy($timeNonceBytes, 0, $dataToSignBytes, $bodyBytes.Length, $timeNonceBytes.Length)
    
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($ApiKey)
    $sigBytes = $hmac.ComputeHash($dataToSignBytes)
    $signature = -join ($sigBytes | ForEach-Object { "{0:x2}" -f $_ })

    # ✅ FIX 3: Added X-REGISTER-KEY for secure TOFU enrollment
    $Headers = @{ 
        "X-API-KEY" = $ApiKey
        "X-TIMESTAMP" = $timestamp.ToString()
        "X-NONCE" = $nonce
        "X-SIGNATURE" = $signature
        "X-REGISTER-KEY" = $Config.RegisterKey
    }
    
    try {
        if ($Method -eq "GET") { 
            return Invoke-RestMethod -Uri "$($Config.Server)$Endpoint" -Method Get -Headers $Headers -UserAgent $Config.UserAgent -TimeoutSec 30 -ErrorAction Stop 
        } else { 
            return Invoke-RestMethod -Uri "$($Config.Server)$Endpoint" -Method Post -Headers $Headers -UserAgent $Config.UserAgent -Body $bodyBytes -ContentType "application/json; charset=utf-8" -TimeoutSec 60 -ErrorAction Stop
        }
    } catch { throw $_ }
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

$h = $env:COMPUTERNAME
$Ticks = 0

while($true) {
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] 📡 Polling Command Center..." -ForegroundColor DarkGray

    try {
        $cmdBody = @{ hostname = $h } | ConvertTo-Json -Compress
        $cmds = Invoke-SignedAPI "/api/commands/get" "POST" $cmdBody
        
        if ($cmds -and $cmds.commands -and $cmds.commands.Count -gt 0) {
            Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] 📥 Received $($cmds.commands.Count) commands." -ForegroundColor Green
            
            foreach($c_raw in $cmds.commands){ 
                $cmdParts = $c_raw -split "::", 2
                $c = $cmdParts[0]
                $sig = if ($cmdParts.Count -gt 1) { $cmdParts[1] } else { "" }
                
                Write-Host "  -> Validating Command: $c" -ForegroundColor Yellow
                
                # ✅ FIX 2: Verify inbound commands using the split COMMAND_SECRET
                $expectedHmac = New-Object System.Security.Cryptography.HMACSHA256
                $expectedHmac.Key = [Text.Encoding]::UTF8.GetBytes($Config.CommandSecret)
                $expectedSigBytes = $expectedHmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($c))
                $expectedSig = -join ($expectedSigBytes | ForEach-Object { "{0:x2}" -f $_ })
                
                if ($sig -ne $expectedSig) {
                    Write-Host "  ❌ HMAC Signature mismatch. Tampering detected. Dropping." -ForegroundColor Red
                    continue
                }
                
                Write-Host "  ✅ Signature Verified." -ForegroundColor Green
                
                if($c -eq "capture_screen" -or $c -eq "start_stream") {
                    Write-Host "  📸 Capturing Screen..." -ForegroundColor Cyan
                    $b64 = Capture-DesktopScreen
                    if ($b64) {
                        Write-Host "  📤 Uploading Screen Data..." -ForegroundColor Cyan
                        $payload = @{ hostname = $h; image = $b64 } | ConvertTo-Json -Compress
                        Invoke-SignedAPI "/api/screen/upload" "POST" $payload | Out-Null
                        Write-Host "  ✅ Upload Complete." -ForegroundColor Green
                    } else { Write-Host "  ❌ Screen capture failed." -ForegroundColor Red }
                }
                
                elseif($c -eq "get_services") {
                    Write-Host "  ⚙️ Gathering Services..." -ForegroundColor Cyan
                    $svcs = Get-Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType | ForEach-Object {
                        @{ Name=$_.Name; DisplayName=$_.DisplayName; Status=$_.Status.value__; StartType=$_.StartType.value__ }
                    }
                    if ($svcs) {
                        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($svcs | ConvertTo-Json -Depth 5 -Compress)))
                        Invoke-SignedAPI "/api/services/update" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                        Write-Host "  ✅ Services Uploaded." -ForegroundColor Green
                    }
                }
                
                elseif($c -eq "get_processes") {
                    Write-Host "  📊 Gathering Processes..." -ForegroundColor Cyan
                    $procs = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CPU, WorkingSet | ForEach-Object {
                        @{ PID=$_.Id; Name=$_.ProcessName; CPU=if($_.CPU){[math]::Round([double]$_.CPU,1)}else{0.0}; MemMB=if($_.WorkingSet){[math]::Round([double]($_.WorkingSet/1MB),1)}else{0.0} }
                    }
                    if ($procs) {
                        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($procs | ConvertTo-Json -Depth 5 -Compress)))
                        Invoke-SignedAPI "/api/processes/update" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                        Write-Host "  ✅ Processes Uploaded." -ForegroundColor Green
                    }
                }
                
                elseif($c -match "^explore:(.*)") {
                    $path = $matches[1]
                    Write-Host "  📂 Browsing File Path: $path" -ForegroundColor Cyan
                    try {
                        if (Test-Path $path) {
                            $items = Get-ChildItem -Path $path -ErrorAction Stop | Select-Object Name, Length, LastWriteTime, Mode | ForEach-Object {
                                @{ Name=$_.Name; Size=$_.Length; Modified=$_.LastWriteTime.ToString("yyyy-MM-dd HH:mm"); Type=if($_.Mode -match "d"){"DIR"}else{"FILE"} }
                            }
                            $res = @{ status="success"; path=$path; items=($items|?{$_ -ne $null}) }
                        } else { $res = @{ status="error"; message="Path not found" } }
                    } catch { $res = @{ status="error"; message=$_.Exception.Message } }
                    
                    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($res | ConvertTo-Json -Depth 5 -Compress)))
                    Invoke-SignedAPI "/api/explorer/update" "POST" (@{hostname=$h; result=$b64} | ConvertTo-Json -Compress) | Out-Null
                    Write-Host "  ✅ File Data Uploaded." -ForegroundColor Green
                }
                
                elseif($c -match "^msg:(.*)") {
                    $msg = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1]))
                    Write-Host "  💬 Displaying Message: $msg" -ForegroundColor Cyan
                    $cmd = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('$msg', 'IT Message', 0, 48)"
                    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -Command `"$cmd`""
                }
            }
        }

        # Terminal Polling
        $t = [Environment]::TickCount
        $termReq = Invoke-SignedAPI "/api/terminal/agent_poll" "POST" (@{hostname=$h; t=$t}|ConvertTo-Json -Compress)
        if ($termReq -and -not [string]::IsNullOrEmpty($termReq.command)) {
            Write-Host "  >_ Executing Terminal Command: $($termReq.command)" -ForegroundColor Magenta
            $cmdOutput = ""
            $cmdLine = $termReq.command.Trim()
            $cmdParts = [System.Text.RegularExpressions.Regex]::Split($cmdLine, '(?<="[^"]*")\s+(?="[^"]*")|(?<=''[^'']*'')\s+(?=''[^'']*'')|\s+') | Where-Object { $_ -ne '' }
            $baseCmd = $cmdParts[0].ToLower()
            $argsArr = if ($cmdParts.Length -gt 1) { $cmdParts[1..($cmdParts.Length-1)] | ForEach-Object { $_ -replace '^"|"$|^''|''$', '' } } else { @() }

            switch ($baseCmd) {
                "ping" { $cmdOutput = & ping.exe @argsArr 2>&1 | Out-String }
                "ipconfig" { $cmdOutput = & ipconfig.exe @argsArr 2>&1 | Out-String }
                "netstat" { $cmdOutput = & netstat.exe @argsArr 2>&1 | Out-String }
                "tasklist" { $cmdOutput = & tasklist.exe @argsArr 2>&1 | Out-String }
                default { $cmdOutput = "ERROR: Command '$baseCmd' is strictly blocked by endpoint security policy." }
            }
            if ([string]::IsNullOrWhiteSpace($cmdOutput)) { $cmdOutput = "`n[Command executed successfully with no output]`n" }
            Invoke-SignedAPI "/api/terminal/agent_push" "POST" (@{ hostname = $h; output = $cmdOutput } | ConvertTo-Json -Compress) | Out-Null
        }

        # Periodic Heartbeat
        if ($Ticks % 3 -eq 0) { 
            Invoke-SignedAPI "/api/heartbeat" "POST" (@{hostname=$h; cpu=5; ram=50; idle=0}|ConvertTo-Json -Compress) | Out-Null
        }
        
        $Ticks++
        Start-Sleep -Seconds $Config.Interval

    } catch { 
        Write-Host "❌ Network or API Error: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep -Seconds 15
    }
}