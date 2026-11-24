# test.ps1 - End-to-end verification of the DHCP DORA simulation on Windows
# Usage (PowerShell):  powershell -ExecutionPolicy Bypass -File .\test.ps1
#
# Scenarios:
#   1. DORA (Discover -> Offer -> Request -> Ack)
#   2. T1 renewal at 50% of the lease
#   3. RELEASE returns the address to FREE
#   4. NAK for an out-of-pool address (192.168.10.250)
#   5. NAK for an address already BOUND to another MAC
#   6. Concurrent clients (SO_REUSEADDR + xid/chaddr filtering) get unique IPs
#   7. Lease-expiry reclamation by the server
param(
    [string]$Bcast = '255.255.255.255',
    [int]$Lease = 16
)

Set-Location $PSScriptRoot
$LogDir    = Join-Path $PSScriptRoot 'test_logs'
$Server    = Join-Path $PSScriptRoot 'dhcp_server.exe'
$Client    = Join-Path $PSScriptRoot 'dhcp_client.exe'
$ServerLog = Join-Path $LogDir 'server.log'
$script:Pass = 0
$script:Fail = 0

function Pass([string]$m)   { $script:Pass++; Write-Host "  [PASS] $m" -ForegroundColor Green }
function Fail([string]$m)   { $script:Fail++; Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Banner([string]$t) { Write-Host ""; Write-Host "================ $t ================" }
function Show([string]$f)   { Get-Content $f | ForEach-Object { Write-Host "    | $_" } }

function Run-Client([string]$log, [string[]]$cliArgs) {
    & $Client @cliArgs -b $Bcast 2>&1 | ForEach-Object { "$_" } |
        Out-File -Encoding ascii -FilePath $log
    return $LASTEXITCODE
}
function IpOf([string]$f) {
    $m = Select-String -Path $f -Pattern '^ASSIGNED_IP=(.+)$' | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
    return ''
}
function LogHas([string]$f, [string]$text) {
    return [bool](Select-String -Path $f -SimpleMatch -Pattern $text -Quiet)
}

if (-not (Test-Path $Server) -or -not (Test-Path $Client)) {
    Write-Host "dhcp_server.exe / dhcp_client.exe missing - run .\build.ps1 first." -ForegroundColor Red
    exit 1
}
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Remove-Item (Join-Path $LogDir '*.log') -ErrorAction SilentlyContinue

$srv = $null
try {
    Banner "Starting DHCP server"
    $srv = Start-Process -FilePath $Server -ArgumentList @('-l', "$Lease", '-b', $Bcast) `
             -RedirectStandardOutput $ServerLog `
             -RedirectStandardError (Join-Path $LogDir 'server_err.log') `
             -NoNewWindow -PassThru
    Start-Sleep -Seconds 1
    if ($srv.HasExited) {
        Write-Host "  server failed to start:" -ForegroundColor Red
        Show (Join-Path $LogDir 'server_err.log')
        exit 1
    }
    Write-Host "  server running (PID $($srv.Id)), log: test_logs\server.log, broadcast $Bcast"
    Write-Host "  (If Windows Firewall asks, click 'Allow access' for dhcp_server/dhcp_client.)"

    # -----------------------------------------------------------------------
    Banner "TEST 1-3: DORA -> T1 Renewal -> Release"
    $log1 = Join-Path $LogDir 't1_lifecycle.log'
    $rc = Run-Client $log1 @('-m', '00:1A:2B:3C:4D:01', '--test-lifecycle')
    Show $log1
    $ip1 = IpOf $log1
    if ($ip1 -and (LogHas $log1 'DHCPACK received -> [BOUND]')) {
        Pass "DORA completed, client BOUND to $ip1"
    } else { Fail "DORA handshake" }
    if (($rc -eq 0) -and (LogHas $log1 'RENEWAL successful') -and
        (LogHas $ServerLog "LEASE RENEWED (T1): $ip1")) {
        Pass "T1 renewal acknowledged by server"
    } else { Fail "T1 renewal" }
    Start-Sleep -Seconds 1
    if (LogHas $ServerLog "RELEASED $ip1 ") {
        Pass "RELEASE freed $ip1 on the server"
    } else { Fail "RELEASE" }

    # -----------------------------------------------------------------------
    Banner "TEST 4: NAK for out-of-pool address"
    $log4 = Join-Path $LogDir 't4_nak.log'
    $rc = Run-Client $log4 @('-m', '00:1A:2B:3C:4D:02', '--test-nak')
    Show $log4
    if (($rc -eq 0) -and (LogHas $ServerLog 'outside the managed pool')) {
        Pass "server sent DHCPNAK for 192.168.10.250"
    } else { Fail "out-of-pool NAK" }

    # -----------------------------------------------------------------------
    Banner "TEST 5: NAK for address bound to another MAC"
    $log5a = Join-Path $LogDir 't5_owner.log'
    $log5b = Join-Path $LogDir 't5_conflict.log'
    $null = Run-Client $log5a @('-m', '00:1A:2B:3C:4D:03', '--test-expire')
    Show $log5a
    $expireStart = Get-Date
    $ip3 = IpOf $log5a
    $rc = Run-Client $log5b @('-m', '00:1A:2B:3C:4D:04', '--test-nak', '-r', $ip3)
    Show $log5b
    if ($ip3 -and ($rc -eq 0) -and (LogHas $ServerLog 'already in use by another MAC')) {
        Pass "server sent DHCPNAK: $ip3 is owned by 00:1A:2B:3C:4D:03"
    } else { Fail "conflict NAK" }

    # -----------------------------------------------------------------------
    Banner "TEST 6: Three concurrent clients on one port"
    $procs = @()
    foreach ($n in 5, 6, 7) {
        $procs += Start-Process -FilePath $Client `
                    -ArgumentList @('-m', "00:1A:2B:3C:4D:0$n", '--test-expire', '-b', $Bcast) `
                    -RedirectStandardOutput (Join-Path $LogDir "t6_client$n.log") `
                    -RedirectStandardError  (Join-Path $LogDir "t6_client${n}_err.log") `
                    -NoNewWindow -PassThru
    }
    $procs | Wait-Process -Timeout 40 -ErrorAction SilentlyContinue
    $ips = @()
    foreach ($n in 5, 6, 7) {
        $f = Join-Path $LogDir "t6_client$n.log"
        $ipn = IpOf $f
        $filt = ''
        $fm = Select-String -Path $f -Pattern 'filtered (\d+) foreign' | Select-Object -First 1
        if ($fm) { $filt = $fm.Matches[0].Groups[1].Value }
        if (-not $ipn) { $shown = '<none>' } else { $shown = $ipn }
        Write-Host "    | 00:1A:2B:3C:4D:0$n -> $shown   (ignored $filt replies meant for other clients)"
        if ($ipn) { $ips += $ipn }
    }
    $distinct = @($ips | Sort-Object -Unique).Count
    if (($ips.Count -eq 3) -and ($distinct -eq 3)) {
        Pass "3 simultaneous clients received 3 distinct addresses"
    } else { Fail "concurrent clients ($($ips.Count) assigned, $distinct distinct)" }

    # -----------------------------------------------------------------------
    Banner "TEST 7: Lease-expiry reclamation"
    Write-Host "  client 00:1A:2B:3C:4D:03 exited without RELEASE; waiting for ${Lease}s lease to expire..."
    $deadline = $expireStart.AddSeconds($Lease + 6)
    $reclaimed = $false
    while ((Get-Date) -le $deadline) {
        if (LogHas $ServerLog "RECLAIMED $ip3 ") { $reclaimed = $true; break }
        Start-Sleep -Seconds 1
    }
    Select-String -Path $ServerLog -SimpleMatch -Pattern 'RECLAIMED' |
        ForEach-Object { Write-Host "    | $($_.Line)" }
    if ($reclaimed) {
        Pass "server reclaimed $ip3 automatically after lease expiry"
    } else { Fail "lease-expiry reclamation" }

    # -----------------------------------------------------------------------
    Banner "Final server lease table"
    Start-Sleep -Seconds 6
    Get-Content $ServerLog -Tail 15 | ForEach-Object { Write-Host $_ }

    Banner "SUMMARY"
    Write-Host "  Passed: $($script:Pass)   Failed: $($script:Fail)   (full server log: test_logs\server.log)"
    if ($script:Fail -eq 0) {
        Write-Host "  ALL TESTS PASSED" -ForegroundColor Green
    } else {
        Write-Host "  SOME TESTS FAILED" -ForegroundColor Red
    }
}
finally {
    if ($srv -and -not $srv.HasExited) {
        Stop-Process -Id $srv.Id -Force
        Write-Host "[test] DHCP server (PID $($srv.Id)) stopped"
    }
}
if ($script:Fail -eq 0) { exit 0 } else { exit 1 }
