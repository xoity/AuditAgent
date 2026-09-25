#!/bin/sh
# Live proof that the on-host watchdog survives a lost session.
#
# Faithful simulation: `apply_transaction` commits when the apply succeeds, so
# to exercise the watchdog we must lose the session in the window between the
# rules being applied and the commit signal. We therefore run the apply in a
# child process and SIGKILL it the moment the rule appears on the host.
set -e

WORKDIR=$(mktemp -d /tmp/auditagent-watchdog-check.XXXXXX)
trap 'rm -rf "$WORKDIR"' EXIT

sudo iptables-save > "$WORKDIR/before"
echo "pre-test rules: $(grep -c '^-A' "$WORKDIR/before" || true)"

cat > "$WORKDIR/apply.py" <<'PY'
import asyncio, subprocess, sys
sys.path.insert(0, "/vagrant")
from audit_agent.devices.linux_iptables import LinuxIptables
from audit_agent.devices.base import CommandResult

async def _exec(command, use_sudo=None):
    argv = ["sh", "-c", command]
    if use_sudo is True or (use_sudo is None and "iptables" in command):
        argv.insert(0, "sudo")
    p = subprocess.run(argv, capture_output=True, text=True)
    return CommandResult(command=command, success=p.returncode == 0,
                         output=p.stdout, error=p.stderr or None,
                         exit_code=p.returncode, execution_time=0.0)

async def main():
    dev = LinuxIptables(host="localhost", username="root")
    dev._ssh_client = object()
    dev.execute_command = _exec

    async def batch(cmds, stop_on_error=True):
        results = [await _exec(c) for c in cmds]
        # Widen the window between "rule applied" and "commit signal" so the
        # harness can kill this process mid-transaction, exactly as a dropped
        # SSH session would.
        import time as _t
        _t.sleep(2)
        return results
    dev.execute_commands_batch = batch

    await dev.apply_transaction(
        ["iptables -A INPUT -p tcp --dport 22222 -j DROP"], timeout=8
    )

asyncio.run(main())
PY

# Run the apply in the background, then kill it as soon as the rule lands.
/opt/aa-venv/bin/python3 "$WORKDIR/apply.py" &
APPLY_PID=$!

for _ in $(seq 1 50); do
  if sudo iptables-save | grep -q -- '--dport 22222 -j DROP'; then
    break
  fi
  sleep 0.2
done

if ! sudo iptables-save | grep -q -- '--dport 22222 -j DROP'; then
  echo "INCONCLUSIVE: rule never applied"
  kill "$APPLY_PID" 2>/dev/null || true
  exit 1
fi
echo "STEP 1: rule applied"

# Session dies here: no commit signal will ever be sent.
sudo kill -9 "$APPLY_PID" 2>/dev/null || true
wait "$APPLY_PID" 2>/dev/null || true
echo "STEP 2: applying process killed (session lost, no commit)"

# Wait past the watchdog timeout.
sleep 10

if sudo iptables-save | grep -q -- '--dport 22222 -j DROP'; then
  echo "FAIL: watchdog did not revert the rule"
  sudo iptables -D INPUT -p tcp --dport 22222 -j DROP 2>/dev/null || true
  exit 1
fi
echo "STEP 3: watchdog reverted the rule with no commit signal"

strip_noise() { grep -v '^#' "$1" | sed -E 's/^(:[A-Z]+ [A-Z]+) \[[0-9]+:[0-9]+\]/\1/'; }

if sudo iptables-save | strip_noise /dev/stdin > "$WORKDIR/after-clean" \
   && strip_noise "$WORKDIR/before" > "$WORKDIR/before-clean" \
   && diff -q "$WORKDIR/before-clean" "$WORKDIR/after-clean" >/dev/null; then
  echo "RESULT: ruleset restored to pre-test state (ignoring save timestamps)"
else
  echo "RESULT: ruleset differs from pre-test state"
  diff "$WORKDIR/before-clean" "$WORKDIR/after-clean" || true
  exit 1
fi
