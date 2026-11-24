# build.ps1 - Build the DHCP DORA project natively on Windows (MinGW-w64 gcc)
# Usage (PowerShell):  powershell -ExecutionPolicy Bypass -File .\build.ps1
Set-Location $PSScriptRoot

if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "gcc not found on PATH." -ForegroundColor Red
    Write-Host "Install MinGW-w64 (e.g. WinLibs or MSYS2 UCRT64) and add its 'bin' folder to PATH."
    exit 1
}

$flags = @('-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2')
foreach ($prog in @('dhcp_server', 'dhcp_client')) {
    Write-Host "gcc $($flags -join ' ') -o $prog.exe $prog.c -lws2_32"
    & gcc @flags -o "$prog.exe" "$prog.c" -lws2_32
    if ($LASTEXITCODE -ne 0) {
        Write-Host "BUILD FAILED ($prog)" -ForegroundColor Red
        exit 1
    }
}
Write-Host "Build OK: dhcp_server.exe, dhcp_client.exe" -ForegroundColor Green
