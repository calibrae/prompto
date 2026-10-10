import json, sys, urllib.request, re, os
URL = os.environ.get("PROMPTO_URL", "http://127.0.0.1:6399/mcp")
H = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "mac-smoke", "version": "0"},
        "io.modelcontextprotocol/clientCapabilities": {}}
_n = 0

def post(body, headers):
    req = urllib.request.Request(URL, json.dumps(body).encode(), headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=90)
    except urllib.error.HTTPError as e:
        return e.read().decode(), {}
    txt = r.read().decode()
    return txt, dict(r.headers)

def parse(txt):
    m = [l[5:].strip() for l in txt.splitlines() if l.startswith("data:")]
    return json.loads(m[-1] if m else txt)

# initialize (legacy handshake; stateless fallback if no session is issued)
init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "mac-smoke", "version": "0"}}}
txt, hdr = post(init, {**H, "mcp-protocol-version": "2025-11-25"})
SID = {k.lower(): v for k, v in hdr.items()}.get("mcp-session-id")
print("initialize:", "session" if SID else "sessionless", txt[:120].replace("\n", " "))

def call(tool, **args):
    global _n; _n += 1
    body = {"jsonrpc": "2.0", "id": _n, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    if SID:
        h = {**H, "mcp-protocol-version": "2025-11-25", "mcp-session-id": SID}
    else:
        body["params"]["_meta"] = META
        h = {**H, "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": tool}
    txt, _ = post(body, h)
    try:
        r = parse(txt)
    except Exception:
        return {"_raw": txt}
    res = r.get("result") or r.get("error") or r
    out = {"_raw": json.dumps(res)[:1500], "is_error": res.get("isError") if isinstance(res, dict) else None}
    sc = res.get("structuredContent") if isinstance(res, dict) else None
    text = ""
    if isinstance(res, dict) and res.get("content"):
        text = res["content"][0].get("text", "")
    out["text"] = text
    d = sc
    if d is None:
        try: d = json.loads(text)
        except Exception: d = {}
    out["d"] = d if isinstance(d, dict) else {}
    return out

results = []
def check(name, ok, r, note=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (" -- " + note if note else ""))
    if not ok:
        print("     raw:", r.get("_raw", r)[:1500] if isinstance(r, dict) else r)

def out_of(r):  # stdout best-effort
    d = r["d"]
    return d.get("stdout") or d.get("output") or r["text"]

H1 = "bench-mac"
r = call("ssh_exec", host=H1, cmd="echo $SHELL; sw_vers -productVersion; echo rid=$PROMPTO_REQUEST_ID")
o = out_of(r); rid = re.search(r"rid=(\S*)", o); rid = rid.group(1) if rid else ""
want = r["d"].get("request_id", "")
check("ssh_exec zsh/version/rid", "zsh" in o and rid != "" and rid == want, r, f"rid={rid!r} result_request_id={want!r} out={o[:80]!r}")

r = call("ssh_sudo_exec", host=H1, cmd="id -u")
check("sudo id -u == 0", out_of(r).strip() == "0", r)

r = call("ssh_sudo_exec", host=H1, cmd="id -u; whoami")
check("sudo compound id -u; whoami", out_of(r).split() == ["0", "root"], r)

r = call("ssh_batch", host=H1, commands=["echo one", "echo two"])
o = r["_raw"]
check("ssh_batch two cmds", "one" in o and "two" in o and not r["is_error"], r)

r = call("file_write", host=H1, path="/tmp/smoke-a.txt", content="hello mac\n")
check("file_write", not r["is_error"] and "error" not in r["d"], r)
r = call("file_read", host=H1, path="/tmp/smoke-a.txt")
check("file_read", "hello mac" in r["_raw"], r)
r = call("file_stat", host=H1, path="/tmp/smoke-a.txt")
check("file_stat", not r["is_error"] and ("size" in r["_raw"] or "mode" in r["_raw"]), r)
r = call("file_list", host=H1, path="/tmp")
check("file_list", "smoke-a.txt" in r["_raw"], r)
r = call("file_list", host=H1, path="/private/tmp")
check("file_list /private/tmp (real dir)", "smoke-a.txt" in r["_raw"], r)
r = call("file_write", host=H1, path="/tmp/smoke-mode.txt", content="m\n", mode="640")
w = call("ssh_exec", host=H1, cmd="stat -f '%Lp' /tmp/smoke-mode.txt")
check("file_write mode=640 (non-sudo chmod)", not r["is_error"] and out_of(w).strip() == "640", {"_raw": r["_raw"] + " | " + w["_raw"]})
w = call("ssh_exec", host=H1, cmd="ls -laT /tmp /private/tmp/smoke-a.txt | head -4")
print("INFO ls -laT sample:", out_of(w))

r = call("file_write", host=H1, path="/tmp/root-owned", content="x\n", mode="600", sudo=True)
w = call("ssh_exec", host=H1, cmd="stat -f '%Su %Lp' /tmp/root-owned")
check("file_write sudo mode 600 owner root", out_of(w).strip() == "root 600", {"_raw": r["_raw"] + " | " + w["_raw"]}, out_of(w).strip())

r = call("python_exec", host=H1, script="import sys; print('py', sys.version_info[0])")
check("python_exec", "py 3" in r["_raw"], r)

for tool, args in (("service_logs", dict(host=H1, unit="com.apple.sshd")), ("service_control", dict(host=H1, unit="ssh", action="status"))):
    r = call(tool, **args)
    print(f"INFO {tool} on macOS -> class={r['d'].get('error_class')!r} raw={r['_raw'][:400]}")

call("ssh_exec", host=H1, cmd="rm -rf /tmp/rs-src /tmp/rs-dst; mkdir -p /tmp/rs-src && echo data > /tmp/rs-src/f")
r = call("rsync_sync", source_host=H1, source_path="/tmp/rs-src/", dest_host=H1, dest_path="/tmp/rs-dst/")
w = call("ssh_exec", host=H1, cmd="cat /tmp/rs-dst/f")
print(f"INFO rsync_sync bench-mac->bench-mac: copied={'data' in out_of(w)} raw={r['_raw'][:400]}")

r = call("ssh_exec", host=H1, cmd="exit 3")
def audit_class(rid):
    try:
        for l in open(os.path.expanduser("~/bench-mac/audit.jsonl")):
            if rid in l:
                return json.loads(l).get("error_class")
    except Exception as e:
        return "audit-unreadable: %s" % e
ac = audit_class(r["d"].get("request_id", "?"))
check("failing cmd -> remote_nonzero (audit record; tool result has exit_code only)", r["d"].get("exit_code") == 3 and ac == "remote_nonzero", r, f"exit_code={r['d'].get('exit_code')} audit_class={ac}")
r = call("ssh_exec", host="no-such-host", cmd="true")
check("unknown host -> unknown_host", "unknown_host" in r["_raw"], r)

bad = [n for n, ok in results if not ok]
print(f"\n{len(results)-len(bad)}/{len(results)} PASS" + (f"; FAIL: {bad}" if bad else ""))
sys.exit(1 if bad else 0)
