# Defensive Lesson — Input Validation

*One short note for the FuzzProbe project. The lesson comes from what the
tool itself found.*

## What input validation is

Input validation means the server checks **every** value it receives — name,
type, length, allowed characters, allowed range — **before** it uses that
value, and rejects anything that does not fit. The check happens on the
server, never only in the browser, because anyone can send a request directly
and skip the browser entirely.

The strongest form is an **allowlist**: the server keeps a list of the
parameters it expects, and the values each one may take, and ignores or
rejects everything else.

## Why it matters — what FuzzProbe showed

FuzzProbe finds parameters the application never shows on its pages. In our
verification run it found two on a test target:

- **`q`** — the server used the value and reflected our unique marker back in
  the response. Reflected input is the starting point of reflected XSS: if a
  value is echoed back without encoding, an attacker can smuggle in a script.
- **`debug`** — the parameter changed the response (length 50 → 88), switching
  on extra behaviour. A leftover `debug`/`admin` parameter in production can
  leak internal information or unlock functions meant only for developers.

Value fuzzing showed the same point from the other side: values such as `'`,
`"`, `../`, `1 OR 1=1` and `{{7*7}}` changed responses. Unchecked, those
shapes of input are how SQL injection, path traversal and template injection
begin. The application should never have trusted them blindly.

So the defensive rule is simple: **a parameter the developer forgot is still
an input the attacker can use.** Validation has to cover the parameters you
did not plan for, not just the ones on the form.

## How to apply it

1. **Allowlist parameters.** Accept only the parameter names the feature
   needs; ignore or reject unknown ones (like `debug` in production).
2. **Validate the value, strictly.** Right type (number, not text), right
   length, right characters — for example a search term is text, never SQL
   or a file path.
3. **Use parameterised queries** for anything that touches a database, so a
   value can never become code.
4. **Encode output.** Anything reflected back into a page is encoded, so a
   marker — or a script — comes back as harmless text.
5. **Fail quietly.** Error messages are generic ("something went wrong");
   database errors and stack traces never reach the user — FuzzProbe's error
   keywords show how much those messages give away.
6. **Turn debug off in production.** Development helpers (`debug`, `admin`,
   `preview`) are removed or locked behind authentication before release.

## One line to remember

*Validate on the server, allowlist what you accept, and never trust a
parameter just because it is not on the page — if the server reads it, an
attacker can send it.*
