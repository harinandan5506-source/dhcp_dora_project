#!/usr/bin/env bash
# test.sh - End-to-end verification of the DHCP DORA simulation (25CSE153)
#
# Scenarios:
#   1. DORA (Discover -> Offer -> Request -> Ack)
#   2. T1 renewal at 50% of the lease
#   3. RELEASE returns the address to FREE
#   4. NAK for an out-of-pool address (192.168.10.250)
#   5. NAK for an address already BOUND to another MAC
#   6. Concurrent clients (SO_REUSEPORT + xid/chaddr filtering) get unique IPs
#   7. Lease-expiry reclamation by the server
set -u
cd "$(dirname "$0")"

LOG_DIR=test_logs
SERVER_LOG=$LOG_DIR/server.log
LEASE_S=16
PASS=0
FAIL=0
SERVER_PID=""

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        echo "[test] DHCP server (PID $SERVER_PID) stopped cleanly"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass()   { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail()   { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
banner() { echo; echo "================ $1 ================"; }
show()   { sed 's/^/    | /' "$1"; }
ip_of()  { sed -n 's/^ASSIGNED_IP=//p' "$1" | head -n1; }

if [ ! -x ./dhcp_server ] || [ ! -x ./dhcp_client ]; then
    echo "Binaries missing - run 'make' first."
    exit 1
fi

banner "Starting DHCP server"
./dhcp_server -l "$LEASE_S" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 1
if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "  server running (PID $SERVER_PID), log: $SERVER_LOG"
else
    echo "  server failed to start:"; show "$SERVER_LOG"; exit 1
fi

# ---------------------------------------------------------------------------
banner "TEST 1-3: DORA -> T1 Renewal -> Release"
./dhcp_client -m 00:1A:2B:3C:4D:01 --test-lifecycle > "$LOG_DIR/t1_lifecycle.log" 2>&1
RC=$?
show "$LOG_DIR/t1_lifecycle.log"
IP1=$(ip_of "$LOG_DIR/t1_lifecycle.log")
if [ -n "$IP1" ] && grep -q "DHCPACK received -> \[BOUND\]" "$LOG_DIR/t1_lifecycle.log"; then
    pass "DORA completed, client BOUND to $IP1"
else
    fail "DORA handshake"
fi
if [ $RC -eq 0 ] && grep -q "RENEWAL successful" "$LOG_DIR/t1_lifecycle.log" \
   && grep -q "LEASE RENEWED (T1): $IP1" "$SERVER_LOG"; then
    pass "T1 renewal acknowledged by server"
else
    fail "T1 renewal"
fi
sleep 1
if grep -q "RELEASED $IP1 " "$SERVER_LOG"; then
    pass "RELEASE freed $IP1 on the server"
else
    fail "RELEASE"
fi

# ---------------------------------------------------------------------------
banner "TEST 4: NAK for out-of-pool address"
./dhcp_client -m 00:1A:2B:3C:4D:02 --test-nak > "$LOG_DIR/t4_nak.log" 2>&1
RC=$?
show "$LOG_DIR/t4_nak.log"
if [ $RC -eq 0 ] && grep -q "outside the managed pool" "$SERVER_LOG"; then
    pass "server sent DHCPNAK for 192.168.10.250"
else
    fail "out-of-pool NAK"
fi

# ---------------------------------------------------------------------------
banner "TEST 5: NAK for address bound to another MAC"
./dhcp_client -m 00:1A:2B:3C:4D:03 --test-expire > "$LOG_DIR/t5_owner.log" 2>&1
show "$LOG_DIR/t5_owner.log"
EXPIRE_START=$(date +%s)
IP3=$(ip_of "$LOG_DIR/t5_owner.log")
./dhcp_client -m 00:1A:2B:3C:4D:04 --test-nak -r "$IP3" > "$LOG_DIR/t5_conflict.log" 2>&1
RC=$?
show "$LOG_DIR/t5_conflict.log"
if [ -n "$IP3" ] && [ $RC -eq 0 ] && grep -q "already in use by another MAC" "$SERVER_LOG"; then
    pass "server sent DHCPNAK: $IP3 is owned by 00:1A:2B:3C:4D:03"
else
    fail "conflict NAK"
fi

# ---------------------------------------------------------------------------
banner "TEST 6: Three concurrent clients on one port"
for n in 5 6 7; do
    ./dhcp_client -m 00:1A:2B:3C:4D:0$n --test-expire > "$LOG_DIR/t6_client$n.log" 2>&1 &
done
wait $(jobs -p | grep -v "^$SERVER_PID\$") 2>/dev/null
IPS=""
for n in 5 6 7; do
    ipn=$(ip_of "$LOG_DIR/t6_client$n.log")
    filt=$(grep -o "filtered [0-9]* foreign" "$LOG_DIR/t6_client$n.log" | awk '{print $2}')
    echo "    | 00:1A:2B:3C:4D:0$n -> ${ipn:-<none>}   (ignored ${filt:-0} replies meant for other clients)"
    IPS="$IPS $ipn"
done
UNIQUE=$(echo $IPS | tr ' ' '\n' | grep -c . )
DISTINCT=$(echo $IPS | tr ' ' '\n' | grep . | sort -u | wc -l)
if [ "$UNIQUE" -eq 3 ] && [ "$DISTINCT" -eq 3 ]; then
    pass "3 simultaneous clients received 3 distinct addresses"
else
    fail "concurrent clients ($UNIQUE assigned, $DISTINCT distinct)"
fi

# ---------------------------------------------------------------------------
banner "TEST 7: Lease-expiry reclamation"
echo "  client 00:1A:2B:3C:4D:03 exited without RELEASE; waiting for ${LEASE_S}s lease to expire..."
DEADLINE=$((EXPIRE_START + LEASE_S + 6))
RECLAIMED=0
while [ "$(date +%s)" -le "$DEADLINE" ]; do
    if grep -q "RECLAIMED $IP3 " "$SERVER_LOG"; then RECLAIMED=1; break; fi
    sleep 1
done
grep "RECLAIMED" "$SERVER_LOG" | sed 's/^/    | /'
if [ $RECLAIMED -eq 1 ]; then
    pass "server reclaimed $IP3 automatically after lease expiry"
else
    fail "lease-expiry reclamation"
fi

# ---------------------------------------------------------------------------
banner "Final server lease table"
sleep 6   # let the concurrent clients' leases expire too
tail -n 15 "$SERVER_LOG"

banner "SUMMARY"
echo "  Passed: $PASS   Failed: $FAIL   (full server log: $SERVER_LOG)"
[ $FAIL -eq 0 ] && echo "  ALL TESTS PASSED" || echo "  SOME TESTS FAILED"
[ $FAIL -eq 0 ]
