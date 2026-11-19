#!/usr/bin/env python3
"""
FuzzProbe (Web) - HTTP Parameter Fuzzer
=======================================
Browser version of FuzzProbe. It starts a small web page on THIS
machine only (http://127.0.0.1:8000). You type the target URL into the
form, press Run, and the results appear in the browser - the scanning
engine and the report are the same as the command-line tool.

Author : Husnain Ghaffar
Use    : ONLY on systems you own or have written permission to test
         (lab apps such as Juice Shop / DVWA in Docker).
Run    : python3 fuzzprobe_web.py   then open http://127.0.0.1:8000
"""

import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fuzzprobe_gui import load_wordlist, scan

PORT = 8000

PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>FuzzProbe - Web</title>
<style>
body {{ background:#0d2818; color:#e8f5e9; font-family:sans-serif;
       margin:40px auto; max-width:820px; padding:0 16px; }}
h1 {{ color:#e8c766; }}
label {{ display:block; margin-top:14px; font-weight:bold; }}
input[type=text], textarea {{ width:100%; padding:8px; margin-top:4px;
  background:#123524; color:#fff; border:1px solid #2e7d32;
  border-radius:4px; }}
button {{ margin-top:18px; padding:10px 26px; background:#1d5c38;
  color:#fff; border:0; border-radius:4px; font-size:15px;
  font-weight:bold; cursor:pointer; }}
pre {{ background:#0a1f12; color:#d7ffd7; padding:14px; border-radius:6px;
  white-space:pre-wrap; word-wrap:break-word; font-size:12.5px; }}
.note {{ color:#b9c9b9; font-size:13px; }}
a {{ color:#e8c766; }}
</style></head><body>
<h1>FuzzProbe - HTTP Parameter Fuzzer</h1>
<p class="note">Lab use only - test systems you own or have written
permission to test. This page runs on your own machine only.</p>
{content}
</body></html>"""

FORM = """
<form method="post" action="/scan">
<label>Target URL</label>
<input type="text" name="url"
       value="http://127.0.0.1:3000/rest/products/search">
<label>Wordlist file (on this machine)</label>
<input type="text" name="wordlist" value="fuzzprobe_params.txt">
<label>...or paste parameter names here (one per line, optional)</label>
<textarea name="names" rows="4"
          placeholder="q&#10;debug&#10;admin"></textarea>
<label>Delay between requests (seconds)</label>
<input type="text" name="delay" value="0.3">
<label style="font-weight:normal">
<input type="checkbox" name="fuzz" checked>
Value fuzzing (test candidates with special values)</label>
<button type="submit">Run Scan</button>
</form>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(PAGE.format(content=FORM))
        else:
            self._send(PAGE.format(content="<p>Page not found. "
                                           '<a href="/">Back</a></p>'),
                       status=404)

    def do_POST(self):
        if self.path != "/scan":
            self._send(PAGE.format(content="<p>Page not found.</p>"),
                       status=404)
            return
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(
            self.rfile.read(length).decode("utf-8", "replace"))
        url = form.get("url", [""])[0].strip()
        pasted = form.get("names", [""])[0].strip()
        wordlist = form.get("wordlist", ["fuzzprobe_params.txt"])[0].strip()
        try:
            delay = float(form.get("delay", ["0.3"])[0])
        except ValueError:
            delay = 0.3
        fuzz = "fuzz" in form

        if not url:
            self._send(PAGE.format(
                content="<p>Please enter a target URL. "
                        '<a href="/">Back</a></p>'))
            return
        if pasted:
            names = [ln.strip() for ln in pasted.splitlines() if ln.strip()]
        else:
            try:
                names = load_wordlist(wordlist)
            except OSError as exc:
                self._send(PAGE.format(
                    content=f"<p>Wordlist problem: {html.escape(str(exc))}"
                            ' <a href="/">Back</a></p>'))
                return

        lines = []
        report, _c, _e = scan(url, names, delay=delay, fuzz_values=fuzz,
                              log=lines.append)
        content = ("<h2>Results</h2><pre>" + html.escape(report) +
                   '</pre><p><a href="/">Run another scan</a></p>')
        self._send(PAGE.format(content=content))

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"FuzzProbe web version running at http://127.0.0.1:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
