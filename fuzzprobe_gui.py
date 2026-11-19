#!/usr/bin/env python3
"""
FuzzProbe (GUI) - HTTP Parameter Fuzzer
=======================================
Window version of FuzzProbe. Same job as the command-line tool: given a
target URL and a wordlist of parameter names, it sends one request per
name with a unique marker value, compares every response with a baseline
request, and reports the parameters the server actually recognises -
with the evidence for each one.

Author : Husnain Ghaffar
Use    : ONLY on systems you own or have written permission to test
         (lab apps such as Juice Shop / DVWA in Docker).
Run    : python3 fuzzprobe_gui.py
"""

import json
import random
import string
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ERROR_KEYWORDS = ["error", "exception", "warning", "sql", "syntax",
                  "stack trace", "fatal", "traceback", "invalid"]
FUZZ_VALUES = ["'", "-1", "0"]


# ----------------------------------------------------------------------
# Core scanning engine (shared logic with the command-line tool)
# ----------------------------------------------------------------------
def fetch(url, timeout=10):
    """One GET request. Returns (status, body, seconds, error)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "FuzzProbe/1.1 (lab tool)"})
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, body, time.time() - start, None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, body, time.time() - start, None
    except Exception as exc:  # timeout, refused, DNS, ...
        return None, "", time.time() - start, str(exc)


def json_keys(body):
    """All keys appearing anywhere in a JSON body, else None."""
    try:
        data = json.loads(body)
    except Exception:
        return None
    keys = set()

    def walk(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                keys.add(key)
                walk(val)
        elif isinstance(obj, list):
            for val in obj:
                walk(val)

    walk(data)
    return keys


def add_param(url, name, value):
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append((name, value))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(query),
                                    parts.fragment))


def make_marker(index):
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"fzp{index}{rand}"


def scan(url, names, delay=0.3, fuzz_values=False, timeout=10, log=print):
    """Run the scan. Returns (report_text, candidates, error_count)."""
    lines = []

    def emit(text=""):
        lines.append(text)
        log(text)

    emit("=" * 64)
    emit("FuzzProbe - HTTP Parameter Fuzzer - Scan Report")
    emit("=" * 64)
    emit(f"Target      : {url}")
    emit("Method      : GET")
    emit(f"Delay       : {delay}s   Timeout: {timeout}s")
    emit("")

    status, body, secs, err = fetch(url, timeout)
    if err:
        emit(f"Baseline request failed: {err}")
        return "\n".join(lines), [], 1
    base = {"status": status, "length": len(body), "time": secs,
            "keys": json_keys(body)}
    emit("[Baseline] (request with no extra parameters)")
    emit(f"  Status: {status}   Length: {len(body)} bytes   "
         f"Time: {secs:.3f}s")
    emit("")
    emit(f"Testing {len(names)} parameters ...")

    candidates = []
    errors = 0
    for i, name in enumerate(names, 1):
        marker = make_marker(i)
        t_status, t_body, t_secs, t_err = fetch(
            add_param(url, name, marker), timeout)
        if t_err:
            errors += 1
            emit(f"  [error] {name}: {t_err}")
            continue
        triggers = []
        if t_status != base["status"]:
            triggers.append(f"status {base['status']}->{t_status}")
        if len(t_body) != base["length"]:
            triggers.append(f"length {base['length']}->{len(t_body)}")
        if marker in t_body:
            triggers.append("marker reflected")
        low = t_body.lower()
        found_kw = [kw for kw in ERROR_KEYWORDS if kw in low]
        base_low = body.lower()
        new_kw = [kw for kw in found_kw if kw not in base_low]
        if new_kw:
            triggers.append("error text: " + ", ".join(new_kw))
        t_keys = json_keys(t_body)
        key_note = ""
        if base["keys"] is not None and t_keys is not None \
                and t_keys != base["keys"]:
            added = sorted(t_keys - base["keys"])
            removed = sorted(base["keys"] - t_keys)
            bits = []
            if added:
                bits.append("+" + ", ".join(added))
            if removed:
                bits.append("-" + ", ".join(removed))
            key_note = " (" + ", ".join(bits) + ")"
            triggers.append("json keys changed" + key_note)
        if triggers:
            cand = {"name": name, "marker": marker, "status": t_status,
                    "length": len(t_body), "time": t_secs,
                    "triggers": triggers, "fuzz": []}
            candidates.append(cand)
            emit(f"  [+] {name} - " + "; ".join(triggers))
        if delay:
            time.sleep(delay)

    if fuzz_values:
        for cand in candidates:
            for value in FUZZ_VALUES:
                v_status, v_body, _v_secs, v_err = fetch(
                    add_param(url, cand["name"], value), timeout)
                if v_err:
                    errors += 1
                    continue
                cand["fuzz"].append((value, v_status, len(v_body)))
                emit(f"  [fuzz] {cand['name']}={value!r} -> "
                     f"status {v_status}, length {len(v_body)}")
                if delay:
                    time.sleep(delay)

    emit("")
    emit(f"[Candidate parameters] {len(candidates)} found")
    for cand in candidates:
        emit(f"  * {cand['name']}")
        emit(f"      baseline : status {base['status']}, "
             f"length {base['length']}")
        emit(f"      test     : status {cand['status']}, "
             f"length {cand['length']}, time {cand['time']:.3f}s")
        emit(f"      marker   : {cand['marker']}")
        emit(f"      triggers : {', '.join(cand['triggers'])}")
        for value, v_status, v_len in cand["fuzz"]:
            emit(f"      value-fuzz: {value!r} -> status {v_status}, "
                 f"length {v_len}")
    emit("")
    emit(f"[Summary] candidates: {len(candidates)}   "
         f"request errors logged: {errors}")
    emit("Note: run only on lab systems you own (Juice Shop / DVWA).")
    return "\n".join(lines), candidates, errors


def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [ln.strip() for ln in fh if ln.strip()
                and not ln.startswith("#")]


# ----------------------------------------------------------------------
# Window (Tkinter)
# ----------------------------------------------------------------------
def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext

    root = tk.Tk()
    root.title("FuzzProbe - HTTP Parameter Fuzzer")
    root.geometry("780x600")
    root.configure(bg="#0d2818")

    state = {"report": ""}

    def label(text, row):
        tk.Label(root, text=text, bg="#0d2818", fg="#e8c766",
                 font=("Helvetica", 10, "bold")).grid(
                     row=row, column=0, sticky="w", padx=10, pady=(10, 2))

    def entry(default, row, browse=False):
        var = tk.StringVar(value=default)
        ent = tk.Entry(root, textvariable=var, width=78,
                       bg="#123524", fg="#ffffff",
                       insertbackground="#ffffff")
        ent.grid(row=row, column=0, sticky="w", padx=10)
        if browse:
            def pick():
                path = filedialog.askopenfilename(
                    title="Choose wordlist file",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
                if path:
                    var.set(path)
            tk.Button(root, text="Browse...", command=pick,
                      bg="#1d5c38", fg="#ffffff").grid(
                          row=row, column=0, sticky="e", padx=10)
        return var

    tk.Label(root, text="FuzzProbe - HTTP Parameter Fuzzer",
             bg="#0d2818", fg="#e8c766",
             font=("Helvetica", 15, "bold")).grid(
                 row=0, column=0, sticky="w", padx=10, pady=(12, 0))
    tk.Label(root, text="Lab use only - test systems you own or have "
                        "written permission to test.",
             bg="#0d2818", fg="#ffffff",
             font=("Helvetica", 9)).grid(row=1, column=0, sticky="w",
                                         padx=10)

    label("Target URL", 2)
    url_var = entry("http://127.0.0.1:3000/rest/products/search", 3)
    label("Wordlist file", 4)
    word_var = entry("fuzzprobe_params.txt", 5, browse=True)
    label("Delay between requests (seconds)", 6)
    delay_var = entry("0.3", 7)
    fuzz_var = tk.BooleanVar(value=True)
    tk.Checkbutton(root, text="Value fuzzing (test candidates with "
                              "special values)",
                   variable=fuzz_var, bg="#0d2818", fg="#ffffff",
                   selectcolor="#123524", activebackground="#0d2818",
                   activeforeground="#e8c766").grid(
                       row=8, column=0, sticky="w", padx=10, pady=(8, 0))

    out = scrolledtext.ScrolledText(root, width=94, height=22,
                                    bg="#0a1f12", fg="#d7ffd7",
                                    font=("Courier", 9))
    out.grid(row=10, column=0, padx=10, pady=10)

    def gui_log(text):
        def append():
            out.insert(tk.END, text + "\n")
            out.see(tk.END)
        root.after(0, append)

    def do_run():
        url = url_var.get().strip()
        if not url:
            messagebox.showwarning("FuzzProbe", "Please enter a target URL.")
            return
        try:
            names = load_wordlist(word_var.get().strip())
        except OSError as exc:
            messagebox.showerror("FuzzProbe", f"Wordlist problem: {exc}")
            return
        try:
            delay = float(delay_var.get())
        except ValueError:
            messagebox.showwarning("FuzzProbe", "Delay must be a number.")
            return
        run_btn.config(state="disabled")
        save_btn.config(state="disabled")
        out.delete("1.0", tk.END)

        def worker():
            report, _c, _e = scan(url, names, delay=delay,
                                  fuzz_values=fuzz_var.get(), log=gui_log)
            state["report"] = report

            def done():
                run_btn.config(state="normal")
                save_btn.config(state="normal")
            root.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def do_save():
        if not state["report"]:
            return
        path = filedialog.asksaveasfilename(
            title="Save report", defaultextension=".txt",
            initialfile="gui_report.txt",
            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(state["report"])
            messagebox.showinfo("FuzzProbe", f"Report saved to:\n{path}")

    btn_frame = tk.Frame(root, bg="#0d2818")
    btn_frame.grid(row=9, column=0, sticky="w", padx=10, pady=(8, 0))
    run_btn = tk.Button(btn_frame, text="Run Scan", command=do_run,
                        bg="#1d5c38", fg="#ffffff",
                        font=("Helvetica", 11, "bold"), width=14)
    run_btn.pack(side="left")
    save_btn = tk.Button(btn_frame, text="Save Report", command=do_save,
                         bg="#1d5c38", fg="#ffffff",
                         font=("Helvetica", 11), width=14, state="disabled")
    save_btn.pack(side="left", padx=8)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
