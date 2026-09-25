#!/bin/sh
# Live proof that the on-host watchdog survives a lost session.
#
# Faithful simulation: `apply_transaction` commits when the apply succeeds, so
# to exercise the watchdog we must lose the session in the window between the
# rules being applied and the commit signal. We therefore run the apply in a
# child process and SIGKILL it the moment the rule appears on the host.
set -e

iptables-save > /tmp/aa-before
echo "pre-test rules: $(grep -c '^-A' /tmp/aa-before || true)"

cat > /tmp/aa-apply.py <<'PY'
import asyncio, subprocess, sys
sys.path.insert(0, "/vagrant")
from audit_agent.devices.linux_iptables import LinuxIptables
from audit_agent.devices.base import CommandResult

async def _exec(command, use_sudo=None):
    p = subprocess.run(["sudo", "sh", "-c", command], capture_output=True, text=True)
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
        _t.sleep(10)
        return results
    dev.execute_commands_batch = batch

    await dev.apply_transaction(
        ["iptables -A INPUT -p tcp --dport 22222 -j DROP"], timeout=5
    )

asyncio.run(main())
PY

# Run the apply in the background, then kill it as soon as the rule lands.
sudo /opt/aa-venv/bin/python3 /tmp/aa-apply.py &
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
sleep 8

if sudo iptables-save | grep -q -- '--dport 22222 -j DROP'; then
  echo "FAIL: watchdog did not revert the rule"
  sudo iptables -D INPUT -p tcp --dport 22222 -j DROP 2>/dev/null || true
  exit 1
fi
echo "STEP 3: watchdog reverted the rule with no commit signal"

strip_noise() { grep -v '^#' "$1" | sed -E 's/^(:[A-Z]+ [A-Z]+) \[[0-9]+:[0-9]+\]/\1/'; }

if sudo iptables-save | strip_noise /dev/stdin > /tmp/aa-after-clean \
   && strip_noise /tmp/aa-before > /tmp/aa-before-clean \
   && diff -q /tmp/aa-before-clean /tmp/aa-after-clean >/dev/null; then
  echo "RESULT: ruleset restored to pre-test state (ignoring save timestamps)"
else
  echo "RESULT: ruleset differs from pre-test state"
  diff /tmp/aa-before-clean /tmp/aa-after-clean || true
  exit 1
fi
