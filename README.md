# FuzzProbe — HTTP Parameter Fuzzer

> A small command-line Python tool that finds **hidden parameters** in a web
> application: you give it a target URL and a wordlist of parameter names, it
> sends one request per name with a unique marker value, compares every
> response against a baseline, and reports the parameters the server actually
> recognises — with the evidence for each one.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple)
![Use](https://img.shields.io/badge/Use-Lab%20Only-green)

## What it does

Many web applications accept parameters that appear nowhere in their pages —
`debug`, `admin`, `preview` and similar. These can leak information or switch
on unintended behaviour. FuzzProbe discovers them: for every name in the
wordlist it sends one request and checks whether the response changed.

## How detection works

1. **Baseline first.** One request with no extra parameters. Its status code,
   body length and response time are recorded.
2. **One request per parameter.** Each request carries a **unique marker**
   value (for example `fzp42xkqjpl`), so a reflected marker proves the server
   saw and used that exact value.
3. **Compare.** A parameter is reported as a candidate when any of these
   triggers fire:
   - status code changed
   - response length changed
   - the marker is reflected in the response body
   - an error keyword appears that was not in the baseline (`sql syntax`,
     `mysql`, `postgresql`, `exception`, `stack trace`, `traceback`, …)
   - JSON keys changed (for JSON responses, keys are compared instead of
     raw body length)
4. **Evidence.** Every candidate is printed live and saved to the report file
   with baseline vs. test values and the trigger that fired.

## Features

**Must-haves (all six, per the brief):**

- CLI input for target URL, wordlist and request delay (`argparse`)
- Baseline request recording status code, body length **and timing**
- One request per parameter, each with a unique marker value
- Anomaly detection: length change, marker reflection, error keywords,
  status change (plus JSON-key comparison)
- Configurable delay between requests, so the target is never hammered
- Report file with evidence for every candidate (baseline vs. test)

**Stretch (all three):**

- `--fuzz-values` — tests each found parameter with 10 special values
  (`'`, `"`, `<fuzzprobe>`, `../`, `1 OR 1=1`, `{{7*7}}`, `;id`, `-1`, `0`,
  `999999999`) and records error reflections
- JSON response comparison — parsed JSON keys instead of raw length
- `--resume` — restarts a stopped scan from the saved wordlist position
  (progress in `fuzzprobe_state.json`; stop any time with Ctrl+C)

## Installation (Kali Linux)

Python 3 is already installed on Kali. The only dependency is `requests`:

```bash
pip install requests
```

## Usage — lab run (Juice Shop)

Start the lab target in Docker, then run the tool against it:

```bash
sudo docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

```bash
python3 fuzzprobe.py -u http://127.0.0.1:3000/rest/products/search -w fuzzprobe_params.txt -d 0.5 --fuzz-values
```

### Example output (verification run)

Verified 18 November 2026 on a local test target
(`http://127.0.0.1:8899/search`): 131 parameters tested, 2 found.

```
[*] Baseline : status 200, length 50, time 0.004s
[*] Testing 131 parameters (delay 0.5s) ...
  [+] q                  length 50->54, marker reflected
  [+] debug              length 50->88
[*] Value-fuzzing candidate parameters ...
```

- **q** — the length changed (50 → 54) and the unique marker came back in
  the response, so the server used the parameter.
- **debug** — the length changed (50 → 88): the parameter switched something
  on in the response.

> **Lab run — OWASP Juice Shop (Docker, own VM), 18 Nov 2026:**
> Target `http://127.0.0.1:3000/rest/products/search`, wordlist
> `fuzzprobe_params.txt` (131 names), delay 0.3s, value fuzzing on.
> Baseline: status 200, 26,963 bytes (all products as JSON).
> **1 candidate found: `q`** — test length 30 bytes (empty result list);
> triggers: length change + JSON keys changed (product keys removed).
> Verified by hand in the browser: `?q=apple` returns Apple Juice and
> Apple Pomace. Value fuzzing on `q`: `'` → 11,640 bytes, `-1` → 924
> bytes, `0` → 14,723 bytes — the value reaches the search query, which
> is why input validation matters (see the defensive-lesson note).
> The full lab report is `final_report.txt`.

## Options

| Option | Description |
|---|---|
| `-u, --url` | Target URL (required) |
| `-w, --wordlist` | Parameter wordlist file, one name per line (required) |
| `-d, --delay` | Delay in seconds between requests (default: `0.5`) |
| `-m, --method` | HTTP method, `GET` or `POST` (default: `GET`) |
| `-o, --output` | Report file (default: `fuzzprobe_report.txt`) |
| `-t, --timeout` | Per-request timeout in seconds (default: `10`) |
| `--fuzz-values` | Value-fuzz every candidate parameter (stretch) |
| `--resume` | Resume from the saved wordlist position (stretch) |

## Project structure

```
FuzzProbe/
├── fuzzprobe.py                    # The tool
├── fuzzprobe_params.txt            # Wordlist — 131 parameter names
├── README.md                       # This file
├── final_report.txt                # Sample report - real lab run (Juice Shop)
├── DEFENSIVE_LESSON_INPUT_VALIDATION.md   # Defensive lesson note
├── fuzzprobe_report.txt            # Generated by a run (evidence)
└── fuzzprobe_state.json            # Generated — resume position
```

## Defensive lesson

See `DEFENSIVE_LESSON_INPUT_VALIDATION.md` — one short note on input
validation: what it is, why hidden parameters make it matter, and how to
apply it.

## Legal — lab only

Test **only** systems you own or have written permission to test (your own
Juice Shop / DVWA in Docker on your own VM). Testing a real website without
permission is unauthorised testing and an offence under the Prevention of
Electronic Crimes Act, 2016 (Pakistan).

## Author

**Husnain Ghaffar** — BS Artificial Intelligence student, passionate about
cybersecurity (CCNA / MCSA / CEH studies).

*Practising web security, one parameter at a time.*
