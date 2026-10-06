# Security-header-checker
A command line tool that checks a website has set important HTTP security headers. It tells the user about missing headers with a severity rating, the risk it imposes and a recommended header to add. It also warns about weakly configured headers and headers that leak backend software versions.

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

## Planned improvements 
- Add batch URL scanning from another file
- JSON output option for scripting and automation
- Only flag unsafe-inline in default-src if no script-src directive present to reduce false positives in CSP header checks
- Use --verbose flag for more detailed error messages
