#!/usr/bin/env python3
"""dashboard.py - zero-dependency local web dashboard for the CUDA Password
Hashing & Brute-Force Demonstration.

Standard library only (http.server, socketserver, subprocess, json, os,
webbrowser, threading). Serves a dark-mode single-page UI on
http://127.0.0.1:8080 and proxies actions to the prebuilt binaries:

  POST /api  {"action": "verify"}                      -> build/test_crypto.exe
  POST /api  {"action": "csv"}                         -> results/benchmark.csv
  POST /api  {"action": "crack", ...}                  -> build/cuda_cracker.exe

Start with `python dashboard.py` or double-click START_DEMO.bat.
"""

import json
import os
import subprocess
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
BUILD = os.path.join(ROOT, "build")
TEST_EXE = os.path.join(BUILD, "test_crypto.exe")
CRACKER_EXE = os.path.join(BUILD, "cuda_cracker.exe")
CSV_PATH = os.path.join(ROOT, "results", "benchmark.csv")
WORDLIST_PATH = os.path.join(ROOT, "data", "wordlist.txt")

PORT = 8080

# --- request validation ------------------------------------------------------
ALGOS = {"sha256", "md5"}
MODES = {"dict", "bruteforce"}
CHARSETS = {"lower", "alnum"}
MAX_PASSWORD_LEN = 55          # single-block hashing limit
CRACK_TIMEOUT_S = 300          # dict + short bruteforce runs finish well inside
VERIFY_TIMEOUT_S = 60

# --- page --------------------------------------------------------------------
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CUDA Password Cracker — Dashboard</title>
<style>
  :root {
    --bg: #0e1116; --panel: #161b22; --panel2: #1c2330; --line: #2a3140;
    --text: #d7dee9; --dim: #8b95a7; --accent: #f2884b; --accent2: #3d8bfd;
    --ok: #3fb950; --err: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 "Segoe UI", system-ui, sans-serif;
  }
  .wrap { max-width: 1060px; margin: 0 auto; padding: 24px 20px 40px; }
  h1 { font-size: 20px; margin: 0 0 4px; letter-spacing: .3px; }
  h1 .gpu { color: var(--accent); }
  .sub { color: var(--dim); font-size: 12.5px; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
  .card {
    background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 16px;
  }
  .card h2 {
    font-size: 12px; text-transform: uppercase; letter-spacing: 1.2px;
    color: var(--dim); margin: 0 0 12px;
  }
  label { display: block; font-size: 12px; color: var(--dim); margin: 10px 0 4px; }
  label:first-of-type { margin-top: 0; }
  select, input[type=text], input[type=file] {
    width: 100%; padding: 8px 10px; border-radius: 7px;
    background: var(--panel2); color: var(--text);
    border: 1px solid var(--line); font: inherit; outline: none;
  }
  select:focus, input:focus { border-color: var(--accent2); }
  .row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .btns { display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap; }
  button {
    padding: 9px 16px; border-radius: 7px; border: 1px solid var(--line);
    background: var(--panel2); color: var(--text); font: inherit;
    font-weight: 600; cursor: pointer; transition: all .15s;
  }
  button:hover { border-color: var(--accent2); }
  button:disabled { opacity: .45; cursor: wait; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #16100b; }
  button.primary:hover { filter: brightness(1.1); }
  .console {
    margin-top: 16px; background: #090c10; border: 1px solid var(--line);
    border-radius: 10px; padding: 12px 14px; height: 340px; overflow: auto;
    font: 12.5px/1.55 Consolas, "Cascadia Mono", monospace; white-space: pre-wrap;
    word-break: break-word;
  }
  .console .cmd { color: var(--accent2); }
  .console .ok  { color: var(--ok); }
  .console .err { color: var(--err); }
  .console .dim { color: var(--dim); }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 12px; }
  th, td { border: 1px solid var(--line); padding: 4px 8px; text-align: right; }
  th:first-child, td:first-child { text-align: left; }
  th { background: var(--panel2); color: var(--dim); position: sticky; top: 0; }
  .csvbox { margin-top: 16px; max-height: 320px; overflow: auto;
    border: 1px solid var(--line); border-radius: 10px; padding: 6px 10px;
    background: var(--panel); }
  .hidden { display: none; }
  .pill { font-size: 11px; padding: 2px 8px; border-radius: 20px;
    border: 1px solid var(--line); color: var(--dim); margin-left: 8px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>CUDA Password Cracker <span class="gpu">RTX&nbsp;3050</span>
      <span class="pill" id="status">idle</span></h1>
  <div class="sub">Pure bitwise SHA-256 / MD5 cracking &mdash; CPU (OpenMP) vs CUDA (constant memory,
      grid-stride, atomicExch early exit). Binaries are executed locally, nothing leaves this machine.</div>

  <div class="grid">
    <div class="card">
      <h2>Attack configuration</h2>
      <label for="algo">Algorithm</label>
      <select id="algo">
        <option value="sha256" selected>sha256</option>
        <option value="md5">md5</option>
      </select>

      <label for="mode">Mode</label>
      <select id="mode">
        <option value="dict" selected>dict &mdash; dictionary attack (data\wordlist.txt)</option>
        <option value="bruteforce">bruteforce &mdash; base-N keyspace scan</option>
      </select>

      <label for="password">Target password (it is hashed locally, then cracked)</label>
      <input type="text" id="password" value="shadow99" spellcheck="false">

      <div id="bfOnly" class="hidden">
        <label>Brute-force parameters</label>
        <div class="row2">
          <div>
            <label for="charset" style="margin-top:0">Charset</label>
            <select id="charset">
              <option value="lower" selected>lower &mdash; a-z (26)</option>
              <option value="alnum">alnum &mdash; a-z A-Z 0-9 (62)</option>
            </select>
          </div>
          <div>
            <label for="length" style="margin-top:0">Length</label>
            <select id="length">
              <option value="4">4</option>
              <option value="5">5</option>
              <option value="6" selected>6</option>
            </select>
          </div>
        </div>
      </div>

      <label for="wordfile">Custom wordlist (.txt, overrides data\wordlist.txt &mdash; dict mode)</label>
      <input type="file" id="wordfile" accept=".txt">

      <div class="btns">
        <button class="primary" id="btnRun" onclick="crack()">Run CUDA Cracker</button>
        <button onclick="verify()">Verify NIST Vectors</button>
        <button onclick="showCsv()">View Benchmark CSV</button>
      </div>
    </div>

    <div class="card">
      <h2>Output console</h2>
      <div class="console" id="out"></div>
    </div>
  </div>

  <div class="csvbox hidden" id="csvbox"></div>
</div>

<script>
const out = document.getElementById("out");
const status = document.getElementById("status");

function ts() {
  return new Date().toLocaleTimeString("en-GB", {hour12: false});
}
function log(text, cls) {
  const span = document.createElement("span");
  if (cls) span.className = cls;
  span.textContent = text + "\n";
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}
function busy(on, what) {
  status.textContent = on ? what : "idle";
  document.querySelectorAll("button").forEach(b => b.disabled = on);
}

document.getElementById("mode").addEventListener("change", e => {
  document.getElementById("bfOnly").classList.toggle("hidden", e.target.value !== "bruteforce");
});

async function callApi(payload) {
  const res = await fetch("/api", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  const data = await res.json();            // {ok, output, error}
  return data;
}

async function crack() {
  const algo = document.getElementById("algo").value;
  const mode = document.getElementById("mode").value;
  const password = document.getElementById("password").value;
  if (!password) { log("!! target password is empty", "err"); return; }
  const payload = {action: "crack", algo: algo, mode: mode, password: password};
  if (mode === "bruteforce") {
    payload.charset = document.getElementById("charset").value;
    payload.length = parseInt(document.getElementById("length").value, 10);
  }
  const wf = document.getElementById("wordfile").files[0];
  if (wf && mode === "dict") {
    if (wf.size > 10 * 1024 * 1024) { log("!! wordlist too large (max 10 MB)", "err"); return; }
    payload.wordlist = await wf.text();
    payload.wordlistName = wf.name;
  }
  busy(true, "cracking\u2026");
  log("[" + ts() + "] $ cuda_cracker.exe " + describeCmd(payload), "cmd");
  const t0 = performance.now();
  try {
    const data = await callApi(payload);
    const secs = ((performance.now() - t0) / 1000).toFixed(2);
    if (data.output) log(data.output.trimEnd());
    if (data.ok) log("[" + ts() + "] done in " + secs + "s", "ok");
    else log("[" + ts() + "] " + (data.error || "failed") + " (" + secs + "s)", "err");
  } catch (e) {
    log("!! request failed: " + e, "err");
  }
  busy(false);
}

function describeCmd(p) {
  let s = "--algo " + p.algo + " --mode " + p.mode + " --password " + p.password;
  if (p.mode === "bruteforce") s += " --charset " + p.charset + " --length " + p.length;
  if (p.wordlist) s += "  [custom wordlist: " + (p.wordlistName || "uploaded") + "]";
  return s;
}

async function verify() {
  busy(true, "verifying\u2026");
  log("[" + ts() + "] $ test_crypto.exe  (NIST vectors, host + device)", "cmd");
  try {
    const data = await callApi({action: "verify"});
    if (data.output) log(data.output.trimEnd());
    log("[" + ts() + "] " + (data.ok ? "verification finished" : (data.error || "failed")),
        data.ok ? "ok" : "err");
  } catch (e) {
    log("!! request failed: " + e, "err");
  }
  busy(false);
}

async function showCsv() {
  busy(true, "loading csv\u2026");
  try {
    const data = await callApi({action: "csv"});
    const box = document.getElementById("csvbox");
    box.classList.remove("hidden");
    if (!data.ok) {
      log("!! " + (data.error || "csv unavailable"), "err");
    } else if (!data.rows || !data.rows.length) {
      box.innerHTML = "<em>No benchmark rows yet &mdash; run <code>--mode benchmark</code> first.</em>";
    } else {
      const cols = Object.keys(data.rows[0]);
      let html = "<table><tr>" + cols.map(c => "<th>" + c + "</th>").join("") + "</tr>";
      for (const r of data.rows) {
        html += "<tr>" + cols.map(c => "<td>" + r[c] + "</td>").join("") + "</tr>";
      }
      box.innerHTML = html + "</table>";
      log("[" + ts() + "] benchmark CSV rendered (" + data.rows.length + " rows)", "ok");
    }
  } catch (e) {
    log("!! request failed: " + e, "err");
  }
  busy(false);
}

log("[" + ts() + "] dashboard ready \u2014 binaries in build\\, data in results\\benchmark.csv", "dim");
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _run(self, argv, timeout):
        """Execute a project binary (argv[0] is a name inside build/) and
        return (ok, combined_output)."""
        exe = os.path.join(BUILD, argv[0])
        if not os.path.isfile(exe):
            return False, f"binary not found: {argv[0]} — run build.ps1 first"
        try:
            proc = subprocess.run(
                [exe] + argv[1:],
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            return proc.returncode == 0, out.strip()
        except subprocess.TimeoutExpired:
            return False, f"timed out after {timeout}s"
        except OSError as exc:
            return False, f"failed to launch {argv[0]}: {exc}"

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404)

    # --------------------------------------------------------------- POST
    def do_POST(self):
        if self.path != "/api":
            self._send_json({"ok": False, "error": "unknown endpoint"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 12 * 1024 * 1024:   # 10 MB wordlist cap + slack
                self._send_json({"ok": False, "error": "request too large"}, 413)
                return
            req = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"ok": False, "error": f"bad JSON: {exc}"}, 400)
            return

        action = req.get("action")

        if action == "verify":
            ok, out = self._run(["test_crypto.exe"], VERIFY_TIMEOUT_S)
            self._send_json({"ok": ok, "output": out})
            return

        if action == "csv":
            if not os.path.isfile(CSV_PATH):
                self._send_json({"ok": False,
                                 "error": "results/benchmark.csv not found - run --mode benchmark first"})
                return
            try:
                with open(CSV_PATH, encoding="utf-8") as f:
                    rows = list(__import__("csv").DictReader(f))
                self._send_json({"ok": True, "rows": rows})
            except OSError as exc:
                self._send_json({"ok": False, "error": f"cannot read CSV: {exc}"})
            return

        if action == "crack":
            algo = req.get("algo", "")
            mode = req.get("mode", "")
            password = str(req.get("password", ""))
            if algo not in ALGOS or mode not in MODES:
                self._send_json({"ok": False, "error": "invalid algo/mode"})
                return
            if not password or len(password) > MAX_PASSWORD_LEN:
                self._send_json({"ok": False,
                                 "error": f"password must be 1..{MAX_PASSWORD_LEN} characters"})
                return

            argv = ["cuda_cracker.exe", "--algo", algo, "--mode", mode,
                    "--password", password]

            if mode == "dict" and req.get("wordlist"):
                words = [ln.rstrip("\r\n")
                         for ln in str(req["wordlist"]).replace("\r\n", "\n").split("\n")]
                words = [w for w in words if w.strip()]
                if not words:
                    self._send_json({"ok": False, "error": "uploaded wordlist is empty"})
                    return
                try:
                    with open(WORDLIST_PATH, "w", encoding="utf-8", newline="\n") as f:
                        f.write("\n".join(words) + "\n")
                except OSError as exc:
                    self._send_json({"ok": False, "error": f"cannot write wordlist: {exc}"})
                    return
                self.log_message(f"wordlist replaced: {len(words)} entries")

            if mode == "bruteforce":
                charset = req.get("charset", "")
                if charset not in CHARSETS:
                    self._send_json({"ok": False, "error": "invalid charset"})
                    return
                try:
                    length = int(req.get("length", 4))
                except (TypeError, ValueError):
                    length = 4
                if length < 1 or length > 8:
                    self._send_json({"ok": False, "error": "length must be 1..8"})
                    return
                argv += ["--charset", charset, "--length", str(length)]

            ok, out = self._run(argv, CRACK_TIMEOUT_S)
            self._send_json({"ok": ok, "output": out})
            return

        self._send_json({"ok": False, "error": f"unknown action: {action}"}, 400)

    def log_message(self, fmt, *args):    # quieter default logging
        print(f"[dashboard] {fmt % args}")


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://127.0.0.1:{PORT}"
    print(f"[dashboard] serving {ROOT}")
    print(f"[dashboard] URL: {url}  (Ctrl+C to stop)")
    threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
