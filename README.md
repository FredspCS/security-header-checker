# Security-header-checker
A command line tool that checks a website has set important HTTP security headers. It tells the user about missing headers with a severity rating, the risk it imposes and a recommended header to add. It also warms about weakly configured headers and headers that leak backend software versions.

## What it does
It sends a request to the provided URL and then runs 3 types of checks on the headers.

1. **Presence:** Are six important security headers set? missing ones are listed with severity rating, the risk it imposes and a recommended header to add.
2. **Weak header values:** Checks for headers that are present but weakly configured. The two headers it checks.
   - `Strict-Transport-Security` Checks for short `max-age` (should be 6 months at least).
   - `Content-Security-Policy` Checks if `unsafe-inline` or `unsafe-eval` directives are present.
3. **Information leaks:** Checks for `server` headers that could reveal a version number of the backend software being used.

## Headers checked and their associated risk of being missing

| Header | Severity | Risk if missing |
|---|---|---|
| `Strict-Transport-Security` | High | Connections may be downgraded to unencrypted HTTP |
| `Content-Security-Policy` | High | Untrusted scripts can run unrestricted |
| `X-Frame-Options` | Medium | A site can be loaded in a hidden iframe (clickjacking) |
| `X-Content-Type-Options` | Medium | Browsers may guess file types which may lead to malicious script execution |
| `Referrer-Policy` | Low | Full URLs may leak to other sites via the Referer header |
| `Permissions-Policy` | Low | Embedded content may access camera, mic or location |

## Usage
```
python Header_Checker.py https://example.com
```
**Only use this on websites you own or have permission to test.**

## Example output

`Are important security headers present?

Header: Strict-Transport-Security
Severity: [High]
Status: NOT present
Risk: Without this, connections can be downgraded to HTTP, allowing interception of traffic on untrusted networks
Recommended: Strict-Transport-Security: max-age=31536000; includeSubDomains

Header: Content-Security-Policy
Severity: [High]
Status: NOT present
Risk: Without this, injected scripts can run with no restriction from the browser
Recommended: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'

Header: X-Frame-Options
Severity: [Medium]
Status: NOT present
Risk: Without this, a site can be loaded inside a hidden iframe, enabling clickjacking attacks
Recommended: X-Frame-Options: DENY

Header: X-Content-Type-Options
Severity: [Medium]
Status: NOT present
Risk: Without this, browsers may guess a file's type instead of trusting the declared one, which can cause uploaded content to be run as a script
Recommended: X-Content-Type-Options: nosniff

Header: Referrer-Policy
Severity: [Low]
Status: NOT present
Risk: Without this, full URLs that may contain sensitive data can leak to external sites via the Referer header
Recommended: Referrer-Policy: strict-origin-when-cross-origin

Header: Permissions-Policy
Severity: [Low]
Status: NOT present
Risk: Without this, embedded malicious content may access sensitive browser inputs like camera or location
Recommended: Permissions-Policy: camera=(), microphone=(), geolocation=()

0/6 security main headers present

Other issues found:

None`


## Planned improvements 
- Add batch URL scanning from another file
- JSON output option for scripting and automation
- Only flag unsafe-inline in default-src if no script-src directive present to reduce false positives in CSP header checks
- Use --verbose flag for more detailed error messages
