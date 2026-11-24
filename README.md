# Simulation of the DHCP Lease Lifecycle (DORA) Using a UDP Broadcast Client-Server Model in C

Course: Computer Networks (25CSE153) - Module 3 (UDP) & Module 4 (DHCP, IPv4 Addressing, Subnetting) -> CO3, CO4

One C codebase that builds natively on **Windows** (MinGW-w64 + Winsock2) and on **Linux** (BSD sockets).

## Contents

| File | Purpose |
|---|---|
| `dhcp_common.h` | Packet struct, RFC 2131/2132 serialization, MAC/IP helpers, logging, portable socket layer |
| `dhcp_server.c` | Lease pool 192.168.10.100-110, `select()` loop, DORA/renew/release/NAK, expiry reclamation |
| `dhcp_client.c` | DORA with retries, T1 renewal, interactive keys, automated test modes |
| `dhcp_server.exe`, `dhcp_client.exe` | Prebuilt 64-bit Windows programs (need no extra DLLs) |
| `build.ps1` / `test.ps1` | Windows PowerShell build and end-to-end test scripts |
| `Makefile` / `test.sh` | Linux build and test (`make`, `make test`); `mingw32-make` also works on Windows |
| `outputs/` | Verified Linux `make` and `test.sh` output, plus the full server log |

## Windows (PowerShell)

```powershell
cd C:\path\to\dhcp_dora_project

# Optional - rebuild from source (needs MinGW-w64 gcc on PATH, e.g. WinLibs or MSYS2):
powershell -ExecutionPolicy Bypass -File .\build.ps1

# Automated tests:
powershell -ExecutionPolicy Bypass -File .\test.ps1

# Live demo - open two or three PowerShell windows:
.\dhcp_server.exe                             # window 1  (Ctrl+C to stop)
.\dhcp_client.exe -m 00:1A:2B:3C:4D:01        # window 2  press r = renew, e = stop renewing, x = release & exit
.\dhcp_client.exe -m 00:1A:2B:3C:4D:02        # window 3  a second client
```

Notes for Windows:
- On first run, **Windows Firewall** may ask about `dhcp_server.exe` / `dhcp_client.exe`: click **Allow access** (Private networks).
- Default broadcast address is `255.255.255.255`. If the PC has **no active network connection**, use
  `-b 127.0.0.1` on both server and client (single client only), e.g. `.\dhcp_server.exe -b 127.0.0.1`.
- Keys in interactive mode are single key presses (no Enter needed).

## Linux

```
make                                   # gcc -Wall -Wextra -Werror -O2
./dhcp_server                          # terminal 1   (-l <sec> lease, -b <ip> broadcast)
./dhcp_client -m 00:1A:2B:3C:4D:01     # terminal 2   keys + Enter: r / e / x
make test                              # automated tests
make clean
```

Default broadcast on Linux is `127.255.255.255` (loopback broadcast, safe from campus DHCP).

## Options

Server: `-l <seconds>` lease time (default 16), `-b <ip>` broadcast address.
Client: `-m <MAC>`, `-b <ip>`, test modes `--test-lifecycle`, `--test-nak [-r <ip>]`, `--test-expire`.
