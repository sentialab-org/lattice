#!/usr/bin/env python3
"""Run a command inside a KVM guest via qemu-agent, from Core01 host.
Usage:
  gexec.py <vm> <timeout> <path> [args...]
  gexec.py <vm> <timeout> --script-file <local-path>
Prints decoded stdout, then EXIT:<code> line.
"""
import base64
import json
import subprocess
import sys
import time

VM = sys.argv[1]
TIMEOUT = int(sys.argv[2])
SSH = [
    "ssh", "-p", "15565", "-i", "/Users/zvwgvx/.ssh/id_ed25519",
    "-o", "UserKnownHostsFile=/Users/zvwgvx/.local/share/lattice/known_hosts",
    "-o", "BatchMode=yes",
    "zvwgvx@14.241.111.182",
]


def virsh_agent(payload):
    blob = "'" + json.dumps(payload) + "'"
    cmd = ["sudo", "virsh", "qemu-agent-command", VM, blob]
    out = subprocess.run(
        SSH + [" ".join(cmd)], capture_output=True, text=True, timeout=60
    ).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise RuntimeError(f"no JSON from agent: {out[:200]}")


if sys.argv[3] == "--script-file":
    import os

    local = sys.argv[4]
    remote = "/tmp/lattice-guest-script.sh"
    with open(local, "rb") as handle:
        blob = base64.b64encode(handle.read()).decode()
    handle_id = virsh_agent(
        {"execute": "guest-file-open", "arguments": {"path": remote, "mode": "w"}}
    )["return"]
    virsh_agent(
        {"execute": "guest-file-write", "arguments": {"handle": handle_id, "buf-b64": blob}}
    )
    virsh_agent({"execute": "guest-file-close", "arguments": {"handle": handle_id}})
    PATH, ARGS = "/bin/bash", [remote]
else:
    PATH, ARGS = sys.argv[3], sys.argv[4:]

req = {"execute": "guest-exec", "arguments": {"path": PATH, "capture-output": True}}
if ARGS:
    req["arguments"]["arg"] = ARGS
pid = virsh_agent(req)["return"]["pid"]
deadline = time.time() + TIMEOUT
code, output = None, ""
while time.time() < deadline:
    time.sleep(2)
    st = virsh_agent({"execute": "guest-exec-status", "arguments": {"pid": pid}})["return"]
    if st.get("exited"):
        code = st.get("exitcode", 0)
        output = base64.b64decode(st.get("out-data", "") or "").decode(errors="replace")
        break
print(output, end="")
print(f"EXIT:{code}")
