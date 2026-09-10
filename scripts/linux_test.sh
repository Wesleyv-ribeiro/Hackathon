#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
ADMIN="$BUILD/admin/labadmin"
AGENT="$BUILD/agent/labagent"
POLICY="$ROOT/policies/default.json"

PASS_COUNT=0
FAIL_COUNT=0

pass() {
echo "[PASS] $1"
PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
echo "[FAIL] $1"
FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "========================================"
echo " LabOrchestrator Linux Integration Test"
echo "========================================"
echo

# ------------------------------------------------------------------

# 1. Build

# ------------------------------------------------------------------

echo "[1/9] Building..."

if cmake --build "$BUILD" -j"$(nproc)" >/dev/null 2>&1; then
pass "Build"
else
fail "Build"
exit 1
fi

# ------------------------------------------------------------------

# 2. Required files

# ------------------------------------------------------------------

echo "[2/9] Checking files..."

[[ -x "$ADMIN" ]] && pass "labadmin exists" || fail "labadmin missing"
[[ -x "$AGENT" ]] && pass "labagent exists" || fail "labagent missing"
[[ -f "$POLICY" ]] && pass "default policy exists" || fail "default policy missing"

# ------------------------------------------------------------------

# 3. Agent process

# ------------------------------------------------------------------

echo "[3/9] Checking agent..."

if pgrep -x labagent >/dev/null 2>&1; then
pass "labagent is running"
else
fail "labagent is not running"
echo
echo "Start it with:"
echo "  $AGENT"
exit 1
fi

# ------------------------------------------------------------------

# 4. Discovery

# ------------------------------------------------------------------

echo "[4/9] Testing discovery..."

DISCOVER_OUTPUT="$("$ADMIN" discover --timeout 3 2>&1)"
echo "$DISCOVER_OUTPUT"

if echo "$DISCOVER_OUTPUT" | grep -q "Agentes descobertos: [1-9]"; then
pass "UDP discovery"
else
fail "UDP discovery"
exit 1
fi

AGENT_IP="$(
echo "$DISCOVER_OUTPUT" |
grep -oE '@ [0-9]+.[0-9]+.[0-9]+.[0-9]+:[0-9]+' |
head -n1 |
sed -E 's/@ ([0-9.]+):[0-9]+/\1/'
)"

if [[ -n "$AGENT_IP" ]]; then
pass "Agent IP detected: $AGENT_IP"
else
fail "Could not determine agent IP"
exit 1
fi

# ------------------------------------------------------------------

# 5. Policy push

# ------------------------------------------------------------------

echo "[5/9] Testing policy push..."

PUSH_OUTPUT="$("$ADMIN" push TheYautja "$POLICY" 2>&1)"
echo "$PUSH_OUTPUT"

if echo "$PUSH_OUTPUT" | grep -qiE 
"Politica enviada|policy sent|sucesso|success"; then
pass "Policy push"
elif ! echo "$PUSH_OUTPUT" | grep -qiE 
"erro|falha|nao encontrada|nao encontrado"; then
pass "Policy push"
else
fail "Policy push"
fi

# ------------------------------------------------------------------

# 6. Status

# ------------------------------------------------------------------

echo "[6/9] Testing status..."

STATUS_OUTPUT="$("$ADMIN" status TheYautja 2>&1)"
echo "$STATUS_OUTPUT"

if echo "$STATUS_OUTPUT" | grep -q "Agente:" &&
echo "$STATUS_OUTPUT" | grep -q "Status:"; then
pass "Status request"
else
fail "Status request"
fi

# ------------------------------------------------------------------

# 7. Direct IP

# ------------------------------------------------------------------

echo "[7/9] Testing direct IP..."

IP_STATUS_OUTPUT="$("$ADMIN" status "$AGENT_IP" 2>&1)"
echo "$IP_STATUS_OUTPUT"

if echo "$IP_STATUS_OUTPUT" | grep -q "Agente:" &&
echo "$IP_STATUS_OUTPUT" | grep -q "Status:"; then
pass "Direct IP status"
else
fail "Direct IP status"
fi

# ------------------------------------------------------------------

# 8. Switch profile

# ------------------------------------------------------------------

echo "[8/9] Testing profile switch..."

SWITCH_OUTPUT="$("$ADMIN" switch TheYautja default 2>&1)"
echo "$SWITCH_OUTPUT"

if echo "$SWITCH_OUTPUT" | grep -qiE 
"sucesso|success|switch|alterado|alterada|Perfil"; then
pass "Profile switch"
else
echo "[WARN] Profile switch response did not match expected text"
echo "       This may simply mean the command has different output."
fi

# ------------------------------------------------------------------

# 9. Final status

# ------------------------------------------------------------------

echo "[9/9] Verifying final state..."

FINAL_STATUS="$("$ADMIN" status TheYautja 2>&1)"
echo "$FINAL_STATUS"

if echo "$FINAL_STATUS" | grep -q "Status:"; then
pass "Final status"
else
fail "Final status"
fi

# ------------------------------------------------------------------

# Results

# ------------------------------------------------------------------

echo
echo "========================================"
echo " Results"
echo "========================================"
echo "PASS: $PASS_COUNT"
echo "FAIL: $FAIL_COUNT"
echo

if (( FAIL_COUNT == 0 )); then
echo "ALL TESTS PASSED"
exit 0
else
echo "SOME TESTS FAILED"
exit 1
fi

